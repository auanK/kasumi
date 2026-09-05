#include "detail.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <filesystem>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace kasumi::transport::local_detail {

State* local_state(void* context) noexcept {
    return static_cast<State*>(context);
}

Error make_error(const std::error_code& error, ErrorCode fallback) {
    ErrorCode code = fallback;
    if (error == std::errc::permission_denied) {
        code = ErrorCode::PermissionDenied;
    } else if (error == std::errc::no_such_file_or_directory) {
        code = ErrorCode::ObjectNotFound;
    }
    return Error{
        .code = code, .message = error.message(), .native_code = error.value()};
}

Error invalid_context_error() {
    return Error{.code = ErrorCode::InvalidContext,
                 .message = "estado do transporte local ausente ou inválido",
                 .native_code = 0};
}

Error invalid_identifier_error() {
    return Error{.code = ErrorCode::InvalidIdentifier,
                 .message = "identificador de objeto inválido",
                 .native_code = 0};
}

std::filesystem::path objects_directory(const State& state) {
    return state.root;
}

namespace {

bool valid_identifier(std::string_view identifier) {
    if (identifier.empty() || identifier.find('\\') != std::string_view::npos) {
        return false;
    }

    const auto path = platform::path::from_utf8(identifier);

    if (path.empty() || path.is_absolute() || path.has_root_name() ||
        path.has_root_directory()) {
        return false;
    }

    for (const auto& component : path) {
        if (component == "." || component == "..") {
            return false;
        }
    }

    const auto normalized = path.lexically_normal();

    return !normalized.empty() && normalized != "." &&
           !normalized.is_absolute() && !normalized.has_root_name() &&
           !normalized.has_root_directory();
}

std::expected<std::filesystem::path, Error>
resolve_object_path(const State& state, std::string_view identifier) {
    if (!valid_identifier(identifier)) {
        return std::unexpected(invalid_identifier_error());
    }

    return objects_directory(state) /
           platform::path::from_utf8(identifier).lexically_normal();
}

Result ensure_parent_directory(const std::filesystem::path& path) {
    const auto parent = path.parent_path();

    if (parent.empty()) {
        return {};
    }

    std::error_code error;
    std::filesystem::create_directories(parent, error);

    if (error) {
        return std::unexpected(make_error(error));
    }

    return {};
}

Result copy_file_overwrite(const std::filesystem::path& source,
                           const std::filesystem::path& destination) {
#if defined(_WIN32)
    if (!CopyFileW(source.c_str(), destination.c_str(), FALSE)) {
        const auto win_err = GetLastError();
        const std::error_code error(static_cast<int>(win_err),
                                    std::system_category());
        return std::unexpected(make_error(error));
    }
    return {};
#else
    std::error_code error;
    std::filesystem::copy_file(
        source,
        destination,
        std::filesystem::copy_options::overwrite_existing,
        error);
    if (error) {
        return std::unexpected(make_error(error));
    }
    return {};
#endif
}

Result local_initialize(void* context) {
    auto* state = local_state(context);

    if (state == nullptr || state->root.empty()) {
        return std::unexpected(invalid_context_error());
    }

    std::error_code error;

    std::filesystem::create_directories(objects_directory(*state), error);

    if (error) {
        return std::unexpected(make_error(error));
    }

    return {};
}

Result local_put(void* context,
                 const std::filesystem::path& source,
                 std::string_view identifier) {
    auto* state = local_state(context);

    if (state == nullptr || state->root.empty()) {
        return std::unexpected(invalid_context_error());
    }

    auto destination = resolve_object_path(*state, identifier);

    if (!destination) {
        return std::unexpected(destination.error());
    }

    auto parent_result = ensure_parent_directory(*destination);

    if (!parent_result) {
        return parent_result;
    }

    std::error_code error;

    const bool source_exists = std::filesystem::is_regular_file(source, error);

    if (error) {
        return std::unexpected(make_error(error));
    }

    if (!source_exists) {
        return std::unexpected(Error{
            .code = ErrorCode::ObjectNotFound,
            .message = "arquivo de origem não existe",
            .native_code = 0,
        });
    }

    return copy_file_overwrite(source, *destination);
}

Result local_get(void* context,
                 std::string_view identifier,
                 const std::filesystem::path& destination) {
    auto* state = local_state(context);

    if (state == nullptr || state->root.empty()) {
        return std::unexpected(invalid_context_error());
    }

    auto source = resolve_object_path(*state, identifier);

    if (!source) {
        return std::unexpected(source.error());
    }

    auto parent_result = ensure_parent_directory(destination);

    if (!parent_result) {
        return parent_result;
    }

    return copy_file_overwrite(*source, destination);
}

PresenceResult local_presence(void* context, std::string_view identifier) {
    auto* state = local_state(context);

    if (state == nullptr || state->root.empty()) {
        return std::unexpected(invalid_context_error());
    }

    auto path = resolve_object_path(*state, identifier);

    if (!path) {
        return std::unexpected(path.error());
    }

    std::error_code error;

    const bool present = std::filesystem::is_regular_file(*path, error);

    if (error && error != std::errc::no_such_file_or_directory) {
        return std::unexpected(make_error(error));
    }

    return present ? Presence::Present : Presence::Absent;
}

ListingResult local_list(void* context) {
    auto* state = local_state(context);

    if (state == nullptr || state->root.empty()) {
        return std::unexpected(invalid_context_error());
    }

    const auto base = objects_directory(*state);

    std::error_code error;
    const bool exists = std::filesystem::exists(base, error);

    if (error) {
        return std::unexpected(make_error(error));
    }

    if (!exists) {
        return std::unexpected(Error{
            .code = ErrorCode::StorageNotFound,
            .message = "diretório de objetos não existe",
            .native_code = 0,
        });
    }

    std::vector<std::string> identifiers;

    std::filesystem::recursive_directory_iterator iterator{
        base,
        std::filesystem::directory_options::skip_permission_denied,
        error};

    if (error) {
        return std::unexpected(make_error(error));
    }

    const std::filesystem::recursive_directory_iterator end;

    while (iterator != end) {
        const auto& entry = *iterator;

        const bool regular = entry.is_regular_file(error);

        if (error) {
            return std::unexpected(make_error(error));
        }

        if (regular) {
            auto relative =
                std::filesystem::relative(entry.path(), base, error);

            if (error) {
                return std::unexpected(make_error(error));
            }

            identifiers.push_back(platform::path::to_logical_utf8(relative));
        }

        iterator.increment(error);

        if (error) {
            return std::unexpected(make_error(error));
        }
    }

    std::ranges::sort(identifiers);

    return identifiers;
}

ListingResult local_list_prefix(void* context, std::string_view prefix) {
    auto* state = local_state(context);
    if (state == nullptr || state->root.empty() || !valid_identifier(prefix)) {
        return std::unexpected(invalid_identifier_error());
    }

    const auto base =
        objects_directory(*state) / platform::path::from_utf8(prefix);
    std::error_code error;
    if (!std::filesystem::is_directory(base, error)) {
        if (error == std::errc::no_such_file_or_directory || !error) {
            return std::unexpected(Error{
                .code = ErrorCode::StorageNotFound,
                .message = "diretório de objetos não existe",
                .native_code = 0,
            });
        }
        return std::unexpected(make_error(error));
    }

    std::vector<std::string> identifiers;
    std::filesystem::directory_iterator iterator{
        base,
        std::filesystem::directory_options::skip_permission_denied,
        error};
    if (error) {
        return std::unexpected(make_error(error));
    }
    const std::filesystem::directory_iterator end;
    while (iterator != end) {
        const auto& entry = *iterator;
        if (entry.is_regular_file(error)) {
            identifiers.push_back(
                platform::path::to_logical_utf8(entry.path().filename()));
        }
        if (error) {
            return std::unexpected(make_error(error));
        }
        iterator.increment(error);
        if (error) {
            return std::unexpected(make_error(error));
        }
    }
    std::ranges::sort(identifiers);
    return identifiers;
}

RemovalResult local_remove(void* context, std::string_view identifier) {
    auto* state = local_state(context);

    if (state == nullptr || state->root.empty()) {
        return std::unexpected(invalid_context_error());
    }

    auto path = resolve_object_path(*state, identifier);

    if (!path) {
        return std::unexpected(path.error());
    }

    std::error_code error;

    const bool removed = std::filesystem::remove(*path, error);

    if (error) {
        return std::unexpected(make_error(error));
    }

    return removed ? Removal::Removed : Removal::AlreadyAbsent;
}

} // namespace

StorageOperations make_storage_operations() noexcept {
    return StorageOperations{
        .initialize = local_initialize,
        .put = local_put,
        .get = local_get,
        .presence = local_presence,
        .list = local_list,
        .list_prefix = local_list_prefix,
        .remove = local_remove,
    };
}

} // namespace kasumi::transport::local_detail
