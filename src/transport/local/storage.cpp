#include "../detail.hpp"
#include "detail.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <filesystem>
#include <new>
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
    return detail::make_error(code, error.message(), error.value());
}

Error invalid_context_error() {
    return detail::make_error(ErrorCode::InvalidContext,
                              "local transport state is missing or invalid",
                              0);
}

Error invalid_identifier_error() {
    return detail::make_error(
        ErrorCode::InvalidIdentifier, "invalid object identifier", 0);
}

std::filesystem::path objects_directory(const State& state) {
    return state.root;
}

namespace {

bool valid_identifier(std::string_view identifier) noexcept {
    return detail::valid_relative_identifier(identifier, false);
}

std::expected<State*, Error> ready_local(void* context) {
    auto* state = local_state(context);
    if (state == nullptr || state->root.empty()) {
        return std::unexpected(invalid_context_error());
    }
    return state;
}

std::expected<std::filesystem::path, Error>
resolve_object_path(const State& state, std::string_view identifier) {
    if (!valid_identifier(identifier)) {
        return std::unexpected(invalid_identifier_error());
    }

    return objects_directory(state) /
           platform::path::from_utf8(identifier).lexically_normal();
}

std::expected<std::filesystem::path, Error>
resolve_ready_path(void* context, std::string_view identifier) {
    auto state = ready_local(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    return resolve_object_path(**state, identifier);
}

Error storage_not_found() {
    return detail::make_error(
        ErrorCode::StorageNotFound, "objects directory does not exist", 0);
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
    std::error_code error;
    const auto dest_status =
        std::filesystem::symlink_status(destination, error);
    if (error && error != std::errc::no_such_file_or_directory) {
        return std::unexpected(make_error(error));
    }
    if (std::filesystem::is_symlink(dest_status) ||
        std::filesystem::is_directory(dest_status)) {
        return std::unexpected(
            detail::make_error(ErrorCode::InvalidContext,
                               "destination cannot be a symlink or directory",
                               0));
    }
#if defined(_WIN32)
    if (!CopyFileW(source.c_str(), destination.c_str(), FALSE)) {
        const auto win_err = GetLastError();
        return std::unexpected(make_error(std::error_code(
            static_cast<int>(win_err), std::system_category())));
    }
    return {};
#else
    error.clear();
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

template <typename Iterator>
ListingResult scan_directory(const std::filesystem::path& base,
                             bool use_filename_only) {
    std::error_code error;
    std::vector<std::string> identifiers;
    Iterator iterator{
        base,
        std::filesystem::directory_options::skip_permission_denied,
        error};
    if (error) {
        return std::unexpected(make_error(error));
    }
    for (const Iterator end; iterator != end; iterator.increment(error)) {
        if (error) {
            return std::unexpected(make_error(error));
        }
        const bool regular = iterator->is_regular_file(error);
        if (error) {
            return std::unexpected(make_error(error));
        }
        if (regular) {
            auto rel =
                use_filename_only
                    ? iterator->path().filename()
                    : std::filesystem::relative(iterator->path(), base, error);
            if (error) {
                return std::unexpected(make_error(error));
            }
            identifiers.push_back(platform::path::to_logical_utf8(rel));
        }
    }
    std::ranges::sort(identifiers);
    return identifiers;
}

Result local_initialize(void* context) {
    auto state = ready_local(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    std::error_code error;
    std::filesystem::create_directories(objects_directory(**state), error);
    return error ? std::unexpected(make_error(error)) : Result{};
}

Result local_put(void* context,
                 const std::filesystem::path& source,
                 std::string_view identifier) {
    auto destination = resolve_ready_path(context, identifier);
    if (!destination) {
        return std::unexpected(destination.error());
    }
    std::error_code error;
    const auto source_status = std::filesystem::symlink_status(source, error);
    if (error && error != std::errc::no_such_file_or_directory) {
        return std::unexpected(make_error(error));
    }
    if (std::filesystem::is_symlink(source_status) ||
        !std::filesystem::is_regular_file(source_status)) {
        return std::unexpected(detail::make_error(
            ErrorCode::ObjectNotFound, "source file does not exist", 0));
    }
    if (auto parent = ensure_parent_directory(*destination); !parent) {
        return parent;
    }
    return copy_file_overwrite(source, *destination);
}

Result local_get(void* context,
                 std::string_view identifier,
                 const std::filesystem::path& destination) {
    auto source = resolve_ready_path(context, identifier);
    if (!source) {
        return std::unexpected(source.error());
    }
    if (auto parent = ensure_parent_directory(destination); !parent) {
        return parent;
    }
    return copy_file_overwrite(*source, destination);
}

PresenceResult local_presence(void* context, std::string_view identifier) {
    auto path = resolve_ready_path(context, identifier);
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
    auto state = ready_local(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    const auto base = objects_directory(**state);
    std::error_code error;
    if (!std::filesystem::exists(base, error)) {
        return std::unexpected(error ? make_error(error) : storage_not_found());
    }
    return scan_directory<std::filesystem::recursive_directory_iterator>(base,
                                                                         false);
}

ListingResult local_list_prefix(void* context, std::string_view prefix) {
    auto state = ready_local(context);
    if (!state || !valid_identifier(prefix)) {
        return std::unexpected(invalid_identifier_error());
    }
    const auto base =
        objects_directory(**state) / platform::path::from_utf8(prefix);
    std::error_code error;
    if (!std::filesystem::is_directory(base, error)) {
        return std::unexpected(
            (error == std::errc::no_such_file_or_directory || !error)
                ? storage_not_found()
                : make_error(error));
    }
    return scan_directory<std::filesystem::directory_iterator>(base, true);
}

RemovalResult local_remove(void* context, std::string_view identifier) {
    auto path = resolve_ready_path(context, identifier);
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

std::expected<void, Error>
validate_destination(const std::filesystem::path& root) {
    for (auto candidate = root;;) {
        std::error_code error;
        const auto status = std::filesystem::status(candidate, error);
        if (error && error != std::errc::no_such_file_or_directory &&
            error != std::errc::not_a_directory) {
            return std::unexpected(make_error(error));
        }
        if (!error && std::filesystem::exists(status)) {
            if (!std::filesystem::is_directory(status)) {
                return std::unexpected(
                    detail::make_error(ErrorCode::InvalidContext,
                                       "local destination traverses a file",
                                       0));
            }
            return {};
        }
        const auto parent = candidate.parent_path();
        if (parent.empty() || parent == candidate) {
            return std::unexpected(
                detail::make_error(ErrorCode::StorageNotFound,
                                   "local destination root is not available",
                                   error.value()));
        }
        candidate = parent;
    }
}

void destroy_local_state(void* context) noexcept {
    delete static_cast<State*>(context);
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

namespace kasumi::transport {

std::expected<Transport, Error>
detail::open_local_backend(detail::LocalConfiguration configuration) {
    if (configuration.root.empty()) {
        return std::unexpected(detail::make_error(
            ErrorCode::InvalidContext, "storage path is invalid", 0));
    }
    if (auto valid = local_detail::validate_destination(configuration.root);
        !valid) {
        return std::unexpected(valid.error());
    }
    auto* state = new (std::nothrow)
        local_detail::State{.root = std::move(configuration.root)};
    if (state == nullptr) {
        return std::unexpected(detail::make_error(
            ErrorCode::Io, "could not allocate local state", 0));
    }
    return Transport{
        .state = TransportStateHandle{state, local_detail::destroy_local_state},
        .storage = local_detail::make_storage_operations(),
    };
}

} // namespace kasumi::transport
