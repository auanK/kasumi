#include "../detail.hpp"
#include "detail.hpp"
#include "platform/cancellation.hpp"
#include "platform/durability.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <new>
#include <system_error>
#include <type_traits>
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

constexpr std::string_view local_staging_dir_name = ".kasumi-staging";

bool valid_identifier(std::string_view identifier) noexcept {
    return detail::valid_relative_identifier(identifier, false);
}

bool is_reserved_staging_identifier(std::string_view identifier) noexcept {
    const auto normalized =
        platform::path::from_utf8(identifier).lexically_normal();
    return !normalized.empty() &&
           platform::path::to_utf8(*normalized.begin()) ==
               local_staging_dir_name;
}

Result reparse_rejected_error(std::string_view context) {
    return std::unexpected(
        detail::make_error(ErrorCode::InvalidContext, std::string{context}, 0));
}

bool contains_reparse_in_relative_chain(const std::filesystem::path& base,
                                        const std::filesystem::path& relative) {
    if (platform::private_storage::is_reparse_or_symlink(base)) {
        return true;
    }
    std::filesystem::path current = base;
    for (const auto& segment : relative) {
        current /= segment;
        if (platform::private_storage::is_reparse_or_symlink(current)) {
            return true;
        }
    }
    return false;
}

std::expected<State*, Error> ready_local(void* context) {
    auto* state = local_state(context);
    if (state == nullptr || state->root.empty()) {
        return std::unexpected(invalid_context_error());
    }
    if (platform::private_storage::is_reparse_or_symlink(state->root)) {
        return std::unexpected(detail::make_error(
            ErrorCode::InvalidContext,
            "local storage root cannot be a symlink or reparse point",
            0));
    }
    return state;
}

std::expected<std::filesystem::path, Error>
resolve_object_path(const State& state, std::string_view identifier) {
    if (!valid_identifier(identifier) ||
        is_reserved_staging_identifier(identifier)) {
        return std::unexpected(invalid_identifier_error());
    }
    const auto base = objects_directory(state);
    const auto normalized =
        platform::path::from_utf8(identifier).lexically_normal();
    if (contains_reparse_in_relative_chain(base, normalized)) {
        return std::unexpected(detail::make_error(
            ErrorCode::InvalidContext,
            "local storage cannot traverse a symlink or reparse point",
            0));
    }
    return base / normalized;
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

Result copy_file_overwrite(
    const std::filesystem::path& source,
    const std::filesystem::path& destination,
    const TransportProgressCallback& callback,
    const std::filesystem::path* staging_directory = nullptr) {
    std::error_code error;
    if (platform::private_storage::is_reparse_or_symlink(source)) {
        return reparse_rejected_error(
            "source cannot be a symlink or reparse point");
    }
    const auto dest_status =
        std::filesystem::symlink_status(destination, error);
    if (error && error != std::errc::no_such_file_or_directory) {
        return std::unexpected(make_error(error));
    }
    if (std::filesystem::is_symlink(dest_status) ||
        std::filesystem::is_directory(dest_status) ||
        platform::private_storage::is_reparse_or_symlink(destination)) {
        return std::unexpected(
            detail::make_error(ErrorCode::InvalidContext,
                               "destination cannot be a symlink or directory",
                               0));
    }

    const auto nonce = platform::random::hex_id(8);
    if (!nonce) {
        return std::unexpected(detail::make_error(
            ErrorCode::Io, "could not generate temporary filename", 0));
    }
    std::filesystem::path staging;
    if (staging_directory != nullptr) {
        if (platform::private_storage::is_reparse_or_symlink(
                *staging_directory)) {
            return reparse_rejected_error(
                "local storage staging directory cannot be a symlink or "
                "reparse point");
        }
        error.clear();
        std::filesystem::create_directories(*staging_directory, error);
        if (error) {
            return std::unexpected(make_error(error));
        }
        staging = *staging_directory / ("put-" + *nonce + ".tmp");
    } else {
        staging = destination;
        staging += ".kasumi-tmp-" + *nonce;
    }

    struct TempGuard {
        const std::filesystem::path& path;
        bool active = true;
        ~TempGuard() noexcept {
            if (!active) {
                return;
            }
            std::error_code cleanup_error;
            std::filesystem::remove(path, cleanup_error);
        }
    } guard{staging};

    TransferProgress progress{.total_objects = 1};
    if (callback) {
        namespace ps = platform::private_storage;
        guard.active = false;
        auto output = ps::create_private_file(staging);
        for (int attempt = 0;
             attempt < 4 && !output && staging_directory != nullptr;
             ++attempt) {
            std::error_code dir_err;
            std::filesystem::create_directories(*staging_directory, dir_err);
            output = ps::create_private_file(staging);
        }
        if (!output) {
            return std::unexpected(
                detail::make_error(ErrorCode::Io, output.error().message, 0));
        }
        guard.active = true;
        const auto size = std::filesystem::file_size(source, error);
        if (!error) {
            progress.total_bytes = size;
        }
        const auto started = std::chrono::steady_clock::now();
        report_transfer(callback, progress);
        std::vector<std::uint8_t> buffer(256U * 1024U);
        const auto copied = ps::stream_regular_file(
            source,
            buffer,
            [&](auto slab) {
                if (platform::cancellation::requested() ||
                    !ps::write_private_file(
                        *output, slab.data(), slab.size())) {
                    return false;
                }
                progress.bytes_transferred += slab.size();
                const auto elapsed =
                    std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - started)
                        .count();
                if (elapsed > 0.0) {
                    progress.bytes_per_second =
                        static_cast<double>(progress.bytes_transferred) /
                        elapsed;
                }
                report_transfer(callback, progress);
                return true;
            },
            progress.total_bytes);
        ps::close_private_file(*output);
        if (!copied) {
            if (platform::cancellation::requested()) {
                return std::unexpected(detail::make_error(
                    ErrorCode::Cancelled, "local transfer cancelled", 0));
            }
            if (copied.error().system_error) {
                return std::unexpected(make_error(copied.error().system_error));
            }
            return std::unexpected(
                detail::make_error(ErrorCode::Io, copied.error().detail, 0));
        }
        progress.total_bytes = progress.bytes_transferred;
    } else {
#if defined(_WIN32)
        DWORD win_err = ERROR_SUCCESS;
        for (unsigned attempt = 0;; ++attempt) {
            if (CopyFileW(source.c_str(), staging.c_str(), TRUE)) {
                win_err = ERROR_SUCCESS;
                break;
            }
            win_err = GetLastError();
            if (win_err == ERROR_PATH_NOT_FOUND &&
                staging_directory != nullptr && attempt < 4) {
                std::error_code dir_err;
                std::filesystem::create_directories(*staging_directory, dir_err);
                continue;
            }
            if (attempt == 5 || (win_err != ERROR_SHARING_VIOLATION &&
                                 win_err != ERROR_LOCK_VIOLATION &&
                                 win_err != ERROR_ACCESS_DENIED)) {
                break;
            }
            Sleep(10UL << attempt);
        }
        if (win_err != ERROR_SUCCESS) {
            if (win_err == ERROR_FILE_EXISTS ||
                win_err == ERROR_ALREADY_EXISTS) {
                guard.active = false;
            }
            return std::unexpected(make_error(std::error_code(
                static_cast<int>(win_err), std::system_category())));
        }
        const auto attributes = GetFileAttributesW(staging.c_str());
        const DWORD cleared = attributes & ~DWORD{FILE_ATTRIBUTE_READONLY};
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            ((attributes & FILE_ATTRIBUTE_READONLY) != 0 &&
             !SetFileAttributesW(staging.c_str(),
                                 cleared == 0 ? FILE_ATTRIBUTE_NORMAL
                                              : cleared))) {
            return std::unexpected(make_error(std::error_code(
                static_cast<int>(GetLastError()), std::system_category())));
        }
#else
        for (int attempt = 0; attempt < 4; ++attempt) {
            error.clear();
            std::filesystem::copy_file(
                source, staging, std::filesystem::copy_options::none, error);
            if (error != std::errc::no_such_file_or_directory ||
                staging_directory == nullptr) {
                break;
            }
            std::error_code dir_err;
            std::filesystem::create_directories(*staging_directory, dir_err);
        }
        if (error) {
            if (error == std::errc::file_exists) {
                guard.active = false;
            }
            return std::unexpected(make_error(error));
        }
#endif
    }
    if (const auto synced = platform::durability::sync_file(staging); !synced) {
        return std::unexpected(
            detail::make_error(ErrorCode::Io, synced.error(), 0));
    }
    if (staging_directory != nullptr) {
        if (const auto synced_staging =
                platform::durability::sync_parent_directory(staging);
            !synced_staging) {
            return std::unexpected(
                detail::make_error(ErrorCode::Io, synced_staging.error(), 0));
        }
        if (const auto moved = platform::durability::move_regular_file(
                staging,
                destination,
                platform::durability::ExistingTarget::Replace);
            !moved) {
            return std::unexpected(
                detail::make_error(ErrorCode::Io, moved.error(), 0));
        }
    } else if (const auto replaced = platform::durability::replace_atomically(
                   staging, destination);
               !replaced) {
        return std::unexpected(
            detail::make_error(ErrorCode::Io, replaced.error(), 0));
    }
    guard.active = false;
    if (const auto synced_dir =
            platform::durability::sync_parent_directory(destination);
        !synced_dir) {
        return std::unexpected(
            detail::make_error(ErrorCode::Io, synced_dir.error(), 0));
    }
    progress.objects_completed = 1;
    report_transfer(callback, progress);
    return {};
}

template <typename Iterator, typename Fn>
std::expected<void, Error> scan_regular_entries(
    const std::filesystem::path& base,
    bool use_filename_only,
    Fn&& on_entry,
    const std::filesystem::path* excluded_top_level_dir = nullptr) {
    if (platform::private_storage::is_reparse_or_symlink(base)) {
        return std::unexpected(detail::make_error(
            ErrorCode::InvalidContext,
            "local storage directory cannot be a symlink or reparse point",
            0));
    }
    std::error_code error;
    Iterator iterator{base, std::filesystem::directory_options::none, error};
    if (error) {
        return std::unexpected(make_error(error));
    }
    for (const Iterator end; iterator != end; iterator.increment(error)) {
        if (error) {
            return std::unexpected(make_error(error));
        }
        const bool is_link = iterator->is_symlink(error);
        if (error) {
            return std::unexpected(make_error(error));
        }
        if (is_link || platform::private_storage::is_reparse_or_symlink(
                           iterator->path())) {
            return std::unexpected(detail::make_error(
                ErrorCode::InvalidContext,
                "local storage cannot traverse a symlink or reparse point",
                0));
        }
        if (excluded_top_level_dir != nullptr &&
            iterator->path() == *excluded_top_level_dir) {
            if constexpr (std::is_same_v<
                              Iterator,
                              std::filesystem::recursive_directory_iterator>) {
                iterator.disable_recursion_pending();
            }
            continue;
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
            if (auto res =
                    on_entry(*iterator, platform::path::to_logical_utf8(rel));
                !res) {
                return res;
            }
        }
    }
    if (error) {
        return std::unexpected(make_error(error));
    }
    return {};
}

template <typename Iterator>
ListingResult scan_directory(
    const std::filesystem::path& base,
    bool use_filename_only,
    const std::filesystem::path* excluded_top_level_dir = nullptr) {
    std::vector<std::string> identifiers;
    auto scanned = scan_regular_entries<Iterator>(
        base,
        use_filename_only,
        [&](const std::filesystem::directory_entry&,
            std::string identifier) -> std::expected<void, Error> {
            identifiers.push_back(std::move(identifier));
            return {};
        },
        excluded_top_level_dir);
    if (!scanned) {
        return std::unexpected(scanned.error());
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

Result local_put_progress(void* context,
                          const std::filesystem::path& source,
                          std::string_view identifier,
                          const TransportProgressCallback& callback) {
    auto state = ready_local(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    auto destination = resolve_object_path(**state, identifier);
    if (!destination) {
        return std::unexpected(destination.error());
    }
    std::error_code error;
    const auto source_status = std::filesystem::symlink_status(source, error);
    if (error && error != std::errc::no_such_file_or_directory) {
        return std::unexpected(make_error(error));
    }
    if (std::filesystem::is_symlink(source_status) ||
        platform::private_storage::is_reparse_or_symlink(source) ||
        !std::filesystem::is_regular_file(source_status)) {
        return std::unexpected(detail::make_error(
            ErrorCode::ObjectNotFound, "source file does not exist", 0));
    }
    if (auto parent = ensure_parent_directory(*destination); !parent) {
        return parent;
    }
    const auto staging_dir = objects_directory(**state) / local_staging_dir_name;
    struct StagingDirLease {
        State& state;
        const std::filesystem::path& staging_dir;
        bool acquired = false;
        ~StagingDirLease() noexcept {
            if (!acquired) {
                return;
            }
            std::lock_guard lock(state.staging_dir_mutex);
            if (state.active_staging_puts > 0) {
                --state.active_staging_puts;
            }
            if (state.active_staging_puts == 0) {
                std::error_code ec;
                std::filesystem::remove(staging_dir, ec);
            }
        }
    } staging_lease{**state, staging_dir};
    {
        std::lock_guard lock((**state).staging_dir_mutex);
        if (platform::private_storage::is_reparse_or_symlink(staging_dir)) {
            return reparse_rejected_error(
                "local storage staging directory cannot be a symlink or "
                "reparse point");
        }
        error.clear();
        std::filesystem::create_directories(staging_dir, error);
        if (error) {
            return std::unexpected(make_error(error));
        }
        ++(**state).active_staging_puts;
        staging_lease.acquired = true;
    }
    return copy_file_overwrite(source, *destination, callback, &staging_dir);
}

Result local_get_progress(void* context,
                          std::string_view identifier,
                          const std::filesystem::path& destination,
                          const TransportProgressCallback& callback) {
    auto source = resolve_ready_path(context, identifier);
    if (!source) {
        return std::unexpected(source.error());
    }
    if (auto parent = ensure_parent_directory(destination); !parent) {
        return parent;
    }
    return copy_file_overwrite(*source, destination, callback);
}

Result local_put(void* context,
                 const std::filesystem::path& source,
                 std::string_view identifier) {
    return local_put_progress(context, source, identifier, {});
}

Result local_get(void* context,
                 std::string_view identifier,
                 const std::filesystem::path& destination) {
    return local_get_progress(context, identifier, destination, {});
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
    const auto staging_dir = base / local_staging_dir_name;
    return scan_directory<std::filesystem::recursive_directory_iterator>(
        base, false, &staging_dir);
}

MetadataListingResult local_list_metadata(void* context) {
    auto state = ready_local(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    const auto base = objects_directory(**state);
    std::error_code error;
    if (!std::filesystem::exists(base, error)) {
        return std::unexpected(error ? make_error(error) : storage_not_found());
    }
    const auto staging_dir = base / local_staging_dir_name;
    std::vector<ObjectMetadata> entries;
    auto scanned =
        scan_regular_entries<std::filesystem::recursive_directory_iterator>(
            base,
            false,
            [&](const std::filesystem::directory_entry& entry,
                std::string identifier) -> std::expected<void, Error> {
                ObjectMetadata meta{.identifier = std::move(identifier)};
                std::error_code attr_error;
                const auto file_size = entry.file_size(attr_error);
                if (!attr_error) {
                    meta.size = static_cast<std::uint64_t>(file_size);
                }
                attr_error.clear();
                const auto mtime = entry.last_write_time(attr_error);
                if (!attr_error) {
                    if (const auto ns =
                            platform::metadata::unix_nanoseconds(mtime);
                        ns && *ns > 0) {
                        meta.modified_at_unix = *ns / 1'000'000'000LL;
                    }
                }
                entries.push_back(std::move(meta));
                return {};
            },
            &staging_dir);
    if (!scanned) {
        return std::unexpected(scanned.error());
    }
    std::ranges::sort(entries, {}, &ObjectMetadata::identifier);
    return entries;
}

ListingResult local_list_prefix(void* context, std::string_view prefix) {
    auto state = ready_local(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (!valid_identifier(prefix) || is_reserved_staging_identifier(prefix)) {
        return std::unexpected(invalid_identifier_error());
    }
    const auto normalized =
        platform::path::from_utf8(prefix).lexically_normal();
    if (contains_reparse_in_relative_chain(objects_directory(**state),
                                           normalized)) {
        return std::unexpected(detail::make_error(
            ErrorCode::InvalidContext,
            "local storage cannot traverse a symlink or reparse point",
            0));
    }
    const auto base = objects_directory(**state) / normalized;
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
    if (platform::private_storage::is_reparse_or_symlink(root)) {
        return std::unexpected(detail::make_error(
            ErrorCode::InvalidContext,
            "local destination cannot be a symlink or reparse point",
            0));
    }
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

Result local_health_check(void* context) {
    auto state = ready_local(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    return validate_destination((*state)->root);
}

} // namespace

StorageOperations make_storage_operations() noexcept {
    return StorageOperations{
        .initialize = local_initialize,
        .put = local_put,
        .get = local_get,
        .presence = local_presence,
        .list = local_list,
        .list_metadata = local_list_metadata,
        .list_prefix = local_list_prefix,
        .remove = local_remove,
        .health_check = local_health_check,
        .put_with_progress = local_put_progress,
        .get_with_progress = local_get_progress,
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
