#include "application/profile.hpp"

#include "application/detail.hpp"
#include "application/sync/journal.hpp"
#include "core/history.hpp"
#include "crypto/content.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/profile_lock.hpp"
#include "platform/random.hpp"
#include "runtime/error.hpp"
#include "runtime/paths.hpp"
#include "runtime/profile.hpp"
#include "runtime/vault.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"
#ifdef KASUMI_MUTATION_FAULT_TESTS
#include "application/profile_fault_test.hpp"
#endif

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace kasumi::application {

namespace {

using platform::private_storage::DirectoryIdentity;
using platform::private_storage::query_directory_identity;

bool has_reparse_point(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD code = GetLastError();
        return code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND;
    }
    return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    static_cast<void>(path);
    return false;
#endif
}

bool valid_retention_policy(const Profile& profile) noexcept {
    return profile.min_history_depth > 0 &&
           profile.min_history_depth <= history::maximum_graph_depth &&
           profile.min_history_age_hours > 0;
}

std::unexpected<ProfileError> fail_profile(ProfileErrorCode code,
                                           std::string detail) {
    return std::unexpected(
        ProfileError{.code = code, .detail = std::move(detail)});
}

ProfileError map_runtime_error(const runtime::Error& err) {
    return ProfileError{
        .code =
            detail::map_runtime_error_code(err.code,
                                           ProfileErrorCode::InvalidName,
                                           ProfileErrorCode::NotFound,
                                           ProfileErrorCode::CredentialFailure,
                                           ProfileErrorCode::StorageFailure,
                                           ProfileErrorCode::ConfigFailure),
        .detail = err.detail,
    };
}
class ScopedConfigLock {
public:
    // Six-clone contention with OS vault RPCs can exceed 2 s under CI load;
    // keep waits bounded at 10 s.
    static std::expected<ScopedConfigLock, ProfileError>
    acquire(const std::filesystem::path& app_data_dir,
            std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
        namespace storage = platform::private_storage;
        std::error_code status_error;
        auto status =
            std::filesystem::symlink_status(app_data_dir, status_error);
        const bool missing =
            status_error == std::errc::no_such_file_or_directory ||
            (!status_error &&
             status.type() == std::filesystem::file_type::not_found);
        if (status_error && !missing) {
            return fail_profile(ProfileErrorCode::StorageFailure,
                                "could not inspect configuration directory: " +
                                    status_error.message());
        }
        if (missing) {
            auto created = storage::create_directory(app_data_dir);
            status_error.clear();
            status =
                std::filesystem::symlink_status(app_data_dir, status_error);
            if (!created &&
                (status_error ||
                 status.type() != std::filesystem::file_type::directory)) {
                return fail_profile(ProfileErrorCode::StorageFailure,
                                    created.error());
            }
        }
        if (status_error ||
            status.type() != std::filesystem::file_type::directory) {
            return fail_profile(ProfileErrorCode::StorageFailure,
                                "configuration path is not a plain directory");
        }
#if defined(_WIN32)
        if (!storage::query_directory_identity(app_data_dir).valid) {
            return fail_profile(ProfileErrorCode::StorageFailure,
                                "configuration path is not an accessible plain "
                                "directory");
        }
#endif
        const auto lock_path = app_data_dir / "config.lock";
        const auto start = std::chrono::steady_clock::now();
        std::string last_error;
        while (true) {
            auto lock_res = platform::acquire_profile_lock(lock_path);
            if (lock_res) {
                return ScopedConfigLock(*lock_res);
            }
            last_error = lock_res.error();
            if (std::chrono::steady_clock::now() - start >= timeout) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return fail_profile(ProfileErrorCode::LockFailure,
                            "could not acquire configuration lock: " +
                                last_error);
    }

    ~ScopedConfigLock() {
        platform::release_profile_lock(handle_);
    }

    ScopedConfigLock(const ScopedConfigLock&) = delete;
    ScopedConfigLock& operator=(const ScopedConfigLock&) = delete;

    ScopedConfigLock(ScopedConfigLock&& other) noexcept
        : handle_(
              std::exchange(other.handle_, platform::invalid_profile_lock)) {
    }

    ScopedConfigLock& operator=(ScopedConfigLock&& other) noexcept {
        if (this != &other) {
            platform::release_profile_lock(handle_);
            handle_ =
                std::exchange(other.handle_, platform::invalid_profile_lock);
        }
        return *this;
    }

private:
    explicit ScopedConfigLock(std::intptr_t handle) noexcept : handle_(handle) {
    }
    std::intptr_t handle_ = platform::invalid_profile_lock;
};

enum class EntryState {
    Absent,
    Present,
    Error
};

struct EntryInfo {
    EntryState state = EntryState::Error;
    bool directory = false;
    bool regular = false;
    bool link = false;
    std::uintmax_t size = 0;

    bool is_plain_dir() const noexcept {
        return state == EntryState::Present && directory && !link;
    }
    bool is_plain_file() const noexcept {
        return state == EntryState::Present && regular && !link;
    }
};

bool path_missing(const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory;
}

// Filesystem presence must be distinguished from access errors: an unreadable
// artifact is never treated as absent.
EntryInfo query_entry(const std::filesystem::path& path) {
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::FailMetadataQuery &&
        fault_test::g_inspect_fault_path == path) {
        return EntryInfo{.state = EntryState::Error};
    }
#endif
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (path_missing(error) ||
        (!error && status.type() == std::filesystem::file_type::not_found)) {
        return EntryInfo{.state = EntryState::Absent};
    }
    if (error) {
        return EntryInfo{.state = EntryState::Error};
    }
    EntryInfo info{.state = EntryState::Present,
                   .directory = std::filesystem::is_directory(status),
                   .regular = std::filesystem::is_regular_file(status),
                   .link = std::filesystem::is_symlink(status)};
    if (!info.link && has_reparse_point(path)) {
        info.link = true;
    }
    if (info.regular) {
        error.clear();
        const auto size = std::filesystem::file_size(path, error);
        if (error) {
            return EntryInfo{.state = EntryState::Error};
        }
        info.size = size;
    }
    return info;
}

enum class LockProbe {
    Inactive,
    Active,
    Error
};

bool can_read_first_byte(const std::filesystem::path& path) {
    std::array<std::uint8_t, 1> buffer{};
    bool read_any = false;
    static_cast<void>(platform::private_storage::stream_regular_file(
        path, buffer, [&](std::span<const std::uint8_t> chunk) {
            if (!chunk.empty()) {
                read_any = true;
                return false;
            }
            return true;
        }));
    return read_any;
}

// Opening an existing lock without creating or modifying it: only an absent
// lock is inactive; any unexpected failure is an error.
LockProbe probe_profile_lock(const std::filesystem::path& path) {
    const auto entry = query_entry(path);
    if (entry.state == EntryState::Absent) {
        return LockProbe::Inactive;
    }
    if (entry.state == EntryState::Error || !entry.regular || entry.link) {
        return LockProbe::Error;
    }
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_path == path &&
        fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::FailLockOpen) {
        return LockProbe::Error;
    }
#endif
#if defined(_WIN32)
    const auto handle =
        CreateFileW(path.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD code = GetLastError();
        if (code == ERROR_SHARING_VIOLATION || code == ERROR_LOCK_VIOLATION) {
            return LockProbe::Active;
        }
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
            return LockProbe::Inactive;
        }
        return LockProbe::Error;
    }
    CloseHandle(handle);
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_path == path &&
        fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::FailLockAcquire) {
        return LockProbe::Error;
    }
#endif
    return LockProbe::Inactive;
#else
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int handle = ::open(path.c_str(), flags);
    if (handle < 0) {
        return errno == ENOENT ? LockProbe::Inactive : LockProbe::Error;
    }
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_path == path &&
        fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::FailLockAcquire) {
        static_cast<void>(::close(handle));
        return LockProbe::Error;
    }
#endif
    if (::flock(handle, LOCK_EX | LOCK_NB) == 0) {
        static_cast<void>(::flock(handle, LOCK_UN));
        static_cast<void>(::close(handle));
        return LockProbe::Inactive;
    }
    const int code = errno;
    static_cast<void>(::close(handle));
    if (code == EWOULDBLOCK || code == EAGAIN) {
        return LockProbe::Active;
    }
    return LockProbe::Error;
#endif
}

struct InspectionTempDirectory {
    std::filesystem::path path;
    DirectoryIdentity identity;
    bool owns = false;

    explicit InspectionTempDirectory(const std::filesystem::path& value)
        : path(value) {
    }

    bool perform_cleanup() {
        if (!owns) {
            return true;
        }
#ifdef KASUMI_MUTATION_FAULT_TESTS
        ++fault_test::g_inspect_cleanup_attempts;
        if (fault_test::inject_cleanup_failure_once(
                fault_test::InspectFaultStage::FailCleanup)) {
            return false;
        }
#endif
        std::error_code error;
        const auto status = std::filesystem::symlink_status(path, error);
        if (path_missing(error) ||
            (!error &&
             status.type() == std::filesystem::file_type::not_found)) {
            owns = false;
            return true;
        }
        if (error || !std::filesystem::is_directory(status) ||
            std::filesystem::is_symlink(status) || has_reparse_point(path)) {
            return false;
        }
        // Ownership is confirmed before deleting anything, so a substituted
        // directory is preserved.
        if (!(query_directory_identity(path) == identity)) {
            return false;
        }

        bool safe = true;
        std::vector<std::filesystem::path> removable;
        std::filesystem::directory_iterator entry(path, error);
        const std::filesystem::directory_iterator end;
        while (!error && entry != end) {
            const auto name = entry->path().filename().string();
            const bool known = name == "db.sqlite" || name == "db.sqlite-wal" ||
                               name == "db.sqlite-shm" ||
                               name == "db.sqlite-journal";
            const auto info = query_entry(entry->path());
            if (!info.is_plain_file() || !known) {
                safe = false;
            } else {
                removable.push_back(entry->path());
            }
            entry.increment(error);
        }
        if (error) {
            safe = false;
        }

#ifdef KASUMI_MUTATION_FAULT_TESTS
        if (fault_test::inject_cleanup_failure_once(
                fault_test::InspectFaultStage::FailCleanupFileRemove)) {
            return false;
        }
#endif

        bool removed = true;
        for (const auto& file : removable) {
            std::error_code remove_error;
            std::filesystem::remove(file, remove_error);
            if (remove_error) {
                removed = false;
            }
        }
        if (!safe || !removed) {
            return false;
        }
#ifdef KASUMI_MUTATION_FAULT_TESTS
        if (fault_test::inject_cleanup_failure_once(
                fault_test::InspectFaultStage::FailCleanupDirectoryRemove)) {
            return false;
        }
#endif
        std::error_code remove_error;
        std::filesystem::remove(path, remove_error);
        if (remove_error) {
            return false;
        }
        std::error_code verify_error;
        if (std::filesystem::exists(path, verify_error) || verify_error) {
            return false;
        }
        owns = false;
        return true;
    }

    ~InspectionTempDirectory() {
        static_cast<void>(perform_cleanup());
    }

    InspectionTempDirectory(const InspectionTempDirectory&) = delete;
    InspectionTempDirectory& operator=(const InspectionTempDirectory&) = delete;
    InspectionTempDirectory(InspectionTempDirectory&&) = delete;
    InspectionTempDirectory& operator=(InspectionTempDirectory&&) = delete;
};

struct SnapshotFileMetadata {
    platform::private_storage::FileIdentity identity;
    std::int64_t last_write = 0;
    std::int64_t change_time = 0;
    bool operator==(const SnapshotFileMetadata&) const = default;
};

// SQLite rollback restores bytes but does not restore native change times.
std::optional<SnapshotFileMetadata>
snapshot_file_metadata(const std::filesystem::path& path) {
#if defined(_WIN32)
    const auto handle =
        CreateFileW(path.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    FILE_BASIC_INFO basic{};
    const bool read = GetFileInformationByHandleEx(
        handle, FileBasicInfo, &basic, sizeof(basic));
    CloseHandle(handle);
    const auto identity = platform::private_storage::query_file_identity(path);
    if (!read || !identity.valid) {
        return std::nullopt;
    }
    return SnapshotFileMetadata{.identity = identity,
                                .last_write = basic.LastWriteTime.QuadPart,
                                .change_time = basic.ChangeTime.QuadPart};
#else
    struct stat status{};
    if (::lstat(path.c_str(), &status) != 0 || !S_ISREG(status.st_mode)) {
        return std::nullopt;
    }
    return SnapshotFileMetadata{
        .identity = {.volume_or_dev = static_cast<std::uint64_t>(status.st_dev),
                     .file_id_low = static_cast<std::uint64_t>(status.st_ino),
                     .file_id_high = 0,
                     .valid = true},
        .last_write =
            static_cast<std::int64_t>(status.st_mtim.tv_sec) * 1'000'000'000LL +
            static_cast<std::int64_t>(status.st_mtim.tv_nsec),
        .change_time =
            static_cast<std::int64_t>(status.st_ctim.tv_sec) * 1'000'000'000LL +
            static_cast<std::int64_t>(status.st_ctim.tv_nsec)};
#endif
}

struct SnapshotFileState {
    Hash hash;
    SnapshotFileMetadata metadata;
    bool operator==(const SnapshotFileState&) const = default;
};

std::optional<SnapshotFileState>
snapshot_file_state(const std::filesystem::path& path) {
    const auto before = snapshot_file_metadata(path);
    if (!before) {
        return std::nullopt;
    }
    const auto hash = crypto::content::hash_file(path);
    const auto after = snapshot_file_metadata(path);
    if (!hash || !after || *before != *after) {
        return std::nullopt;
    }
    return SnapshotFileState{.hash = *hash, .metadata = *after};
}

// Copy a stable database and its transaction sidecars before SQLite opens the
// disposable copy and applies any hot journal.
bool take_sqlite_snapshot(const std::filesystem::path& source,
                          const std::filesystem::path& destination,
                          bool wal_was_present,
                          bool rollback_was_present) {
    const auto sources = detail::sqlite_sidecar_paths(source);
    const auto& wal_source = sources[0];
    const auto& rollback_source = sources[2];
    const auto wal = query_entry(wal_source);
    const auto rollback = query_entry(rollback_source);
    if ((wal_was_present && wal.state != EntryState::Present) ||
        (rollback_was_present &&
         (rollback.state != EntryState::Present || rollback.size == 0)) ||
        wal.state == EntryState::Error ||
        (wal.state == EntryState::Present && (!wal.regular || wal.link)) ||
        rollback.state == EntryState::Error ||
        (rollback.state == EntryState::Present &&
         (!rollback.regular || rollback.link)) ||
        (wal.state == EntryState::Present && wal.size > 0 &&
         rollback.state == EntryState::Present && rollback.size > 0)) {
        return false;
    }

    const auto database_before = snapshot_file_state(source);
    if (!database_before) {
        return false;
    }
    struct Sidecar {
        std::filesystem::path source;
        std::string_view suffix;
        std::optional<SnapshotFileState> before;
    };
    std::vector<Sidecar> sidecars;
    if (wal.state == EntryState::Present) {
        auto state = snapshot_file_state(wal_source);
        if (!state) {
            return false;
        }
        sidecars.push_back(Sidecar{wal_source, "-wal", *state});
    }
    if (rollback.state == EntryState::Present && rollback.size > 0) {
        auto state = snapshot_file_state(rollback_source);
        if (!state) {
            return false;
        }
        sidecars.push_back(Sidecar{rollback_source, "-journal", *state});
    }

#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::ConcurrentSnapshotBarrier &&
        fault_test::g_inspect_fault_observer) {
        fault_test::g_inspect_fault_observer(
            fault_test::InspectFaultStage::ConcurrentSnapshotBarrier);
    }
#endif
    std::error_code error;
    if (!std::filesystem::copy_file(source, destination, error) || error) {
        return false;
    }
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::ConcurrentSnapshotBarrier &&
        fault_test::g_inspect_fault_observer) {
        fault_test::g_inspect_fault_observer(
            fault_test::InspectFaultStage::SnapshotDatabaseCopied);
    }
#endif
    for (const auto& item : sidecars) {
        auto sidecar_dest = destination;
        sidecar_dest += item.suffix;
        error.clear();
        if (!std::filesystem::copy_file(item.source, sidecar_dest, error) ||
            error) {
            return false;
        }
    }
    const auto database_after = snapshot_file_state(source);
    if (!database_after || *database_after != *database_before) {
        return false;
    }
    for (const auto& item : sidecars) {
        const auto state = snapshot_file_state(item.source);
        if (!state || *state != *item.before) {
            return false;
        }
    }
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::ConcurrentSnapshotBarrier &&
        fault_test::g_inspect_fault_observer) {
        fault_test::g_inspect_fault_path = destination;
        fault_test::g_inspect_fault_observer(
            fault_test::InspectFaultStage::SnapshotReady);
    }
#endif
    return true;
}

auto find_profile(std::vector<runtime::ProfileData>& profiles,
                  std::string_view name) {
    return std::ranges::find_if(profiles, [&](const auto& p) {
        return p.name == name;
    });
}

auto find_profile_name_conflict(std::vector<runtime::ProfileData>& profiles,
                                std::string_view name,
                                std::string_view except = {}) {
    const auto folded = runtime::fold_profile_name(name);
    return std::ranges::find_if(profiles, [&](const auto& profile) {
        return profile.name != except &&
               runtime::fold_profile_name(profile.name) == folded;
    });
}

std::expected<void, ProfileError>
validate_profile_locations(const Profile& profile) {
    if (auto valid =
            validate_profile_field(ProfileField::LocalPath,
                                   platform::path::to_utf8(profile.local_dir));
        !valid) {
        return valid;
    }
    return validate_profile_field(ProfileField::RemotePath, profile.remote_dir);
}

struct LockedConfig {
    ScopedConfigLock lock;
    std::filesystem::path config_path;
    std::vector<runtime::ProfileData> profiles;
};

std::expected<LockedConfig, ProfileError>
load_profiles_locked(const std::filesystem::path& app_data_dir,
                     bool not_found_as_empty = false,
                     std::string_view not_found_detail = {}) {
    auto lock = ScopedConfigLock::acquire(app_data_dir);
    if (!lock) {
        return std::unexpected(lock.error());
    }
    auto config_path = app_data_dir / "config.toml";
    auto profiles_res = runtime::load_profiles(config_path);
    std::vector<runtime::ProfileData> profiles;
    if (!profiles_res) {
        if (not_found_as_empty &&
            profiles_res.error().code == runtime::ErrorCode::ConfigNotFound) {
            return LockedConfig{
                .lock = std::move(*lock),
                .config_path = std::move(config_path),
                .profiles = {},
            };
        }
        if (!not_found_detail.empty() &&
            profiles_res.error().code == runtime::ErrorCode::ConfigNotFound) {
            return fail_profile(ProfileErrorCode::NotFound,
                                std::string(not_found_detail));
        }
        return std::unexpected(map_runtime_error(profiles_res.error()));
    }
    return LockedConfig{
        .lock = std::move(*lock),
        .config_path = std::move(config_path),
        .profiles = std::move(*profiles_res),
    };
}

struct KeyBytesWiper {
    runtime::vault::KeyBytes& key;
    bool active = true;
    void release() noexcept {
        if (active) {
            crypto::secure_memory::wipe(key.data(), key.size());
            active = false;
        }
    }
    ~KeyBytesWiper() {
        release();
    }
};

runtime::KeyStorage to_runtime_key_storage(KeyStorage storage) noexcept {
    switch (storage) {
        case KeyStorage::Vault:
            return runtime::KeyStorage::Vault;
        case KeyStorage::File:
            return runtime::KeyStorage::File;
        case KeyStorage::Memory:
            return runtime::KeyStorage::Memory;
    }
    return runtime::KeyStorage::Vault;
}

KeyStorage to_app_key_storage(runtime::KeyStorage storage) noexcept {
    switch (storage) {
        case runtime::KeyStorage::Vault:
            return KeyStorage::Vault;
        case runtime::KeyStorage::File:
            return KeyStorage::File;
        case runtime::KeyStorage::Memory:
            return KeyStorage::Memory;
    }
    return KeyStorage::Vault;
}

std::expected<runtime::vault::KeyBytes, runtime::Error>
resolve_profile_credentials(const ProfileCredentials& credentials) {
    if (const auto* hex = std::get_if<MasterKeyHex>(&credentials)) {
        return runtime::vault::decode_hex(hex->value);
    }
    if (const auto* pair = std::get_if<PasswordPair>(&credentials)) {
        return runtime::vault::derive(pair->password, pair->salt_password);
    }
    return std::unexpected(runtime::Error{
        .code = runtime::ErrorCode::KeyInvalid, .detail = "uninitialized"});
}
} // namespace

std::string_view to_string(KeyStorage storage) noexcept {
    return runtime::to_string(to_runtime_key_storage(storage));
}

std::expected<void, ProfileError>
validate_profile_field(ProfileField field, std::string_view value) {
    if (field == ProfileField::Name) {
        if (!runtime::is_valid_profile_name(value)) {
            return fail_profile(ProfileErrorCode::InvalidName,
                                "invalid profile name");
        }
    } else if (field == ProfileField::LocalPath) {
        if (!platform::path::from_utf8(value).is_absolute()) {
            return fail_profile(ProfileErrorCode::StorageFailure,
                                "local path must be absolute");
        }
    } else if (auto valid = transport::validate_transport_location(value);
               !valid) {
        return fail_profile(ProfileErrorCode::StorageFailure,
                            transport::describe(valid.error()));
    }
    return {};
}

std::expected<std::vector<Profile>, ProfileError>
list_profiles(const ExecutionEnvironment& environment) {
    auto config_path = environment.app_data_dir / "config.toml";
    auto profiles_res = runtime::load_profiles(config_path);

    if (!profiles_res) {
        if (profiles_res.error().code == runtime::ErrorCode::ConfigNotFound) {
            return std::vector<Profile>{};
        }
        return std::unexpected(map_runtime_error(profiles_res.error()));
    }

    std::vector<Profile> result;
    result.reserve(profiles_res->size());
    for (const auto& p : *profiles_res) {
        result.push_back(
            Profile{.name = p.name,
                    .local_dir = p.local_dir,
                    .remote_dir = p.remote_dir,
                    .min_history_depth = p.min_history_depth,
                    .min_history_age_hours = p.min_history_age_hours,
                    .key_storage = to_app_key_storage(p.key_storage)});
    }
    return result;
}

std::expected<void, ProfileError>
create_profile(const ExecutionEnvironment& environment,
               Profile profile,
               ProfileCredentials credentials) {
    std::expected<runtime::vault::KeyBytes, runtime::Error> master_key_res =
        std::unexpected(runtime::Error{.code = runtime::ErrorCode::KeyInvalid,
                                       .detail = "uninitialized"});

    auto do_create = [&]() -> std::expected<void, ProfileError> {
        if (!runtime::is_valid_profile_name(profile.name)) {
            return fail_profile(ProfileErrorCode::InvalidName,
                                "invalid profile name");
        }
        if (!valid_retention_policy(profile)) {
            return fail_profile(ProfileErrorCode::ConfigFailure,
                                "invalid retention policy");
        }
        if (const auto valid = validate_profile_locations(profile); !valid) {
            return valid;
        }

        master_key_res = resolve_profile_credentials(credentials);

        if (!master_key_res) {
            return std::unexpected(map_runtime_error(master_key_res.error()));
        }

        auto loaded = load_profiles_locked(environment.app_data_dir, true);
        if (!loaded) {
            return std::unexpected(loaded.error());
        }
        auto& profiles = loaded->profiles;
        const auto& config_path = loaded->config_path;

        if (find_profile_name_conflict(profiles, profile.name) !=
            profiles.end()) {
            return fail_profile(ProfileErrorCode::AlreadyExists,
                                "profile already exists");
        }

        auto paths_res = runtime::resolve_profile_paths(
            environment.app_data_dir, profile.name);
        if (!paths_res) {
            return std::unexpected(map_runtime_error(paths_res.error()));
        }

        if (query_entry(paths_res->profile_dir).state != EntryState::Absent ||
            query_entry(paths_res->key_path).state != EntryState::Absent) {
            return fail_profile(
                ProfileErrorCode::StorageFailure,
                "profile infrastructure already exists on disk");
        }

        auto ensure_res = runtime::ensure_profile_directory(*paths_res);
        if (!ensure_res) {
            return std::unexpected(map_runtime_error(ensure_res.error()));
        }

        auto rollback_failure = [&](ProfileErrorCode code, std::string detail) {
            if (auto remove_res = runtime::remove_profile_directory(*paths_res);
                !remove_res) {
                detail +=
                    "; rollback also failed: " + remove_res.error().detail;
            }
            return fail_profile(code, std::move(detail));
        };

        if (profile.key_storage == KeyStorage::File) {
            if (!runtime::vault::write(paths_res->key_path, *master_key_res)) {
                return rollback_failure(ProfileErrorCode::StorageFailure,
                                        "failed to save vault");
            }
        } else if (profile.key_storage == KeyStorage::Vault) {
            if (auto vault_res = runtime::vault::write_vault(
                    paths_res->key_path, *master_key_res);
                !vault_res) {
                return rollback_failure(ProfileErrorCode::StorageFailure,
                                        vault_res.error().detail);
            }
        }

        if (!state_storage::initialize(paths_res->database_path)) {
            return rollback_failure(ProfileErrorCode::StorageFailure,
                                    "failed to initialize profile database");
        }

        profiles.push_back(
            runtime::ProfileData{profile.name,
                                 profile.local_dir,
                                 profile.remote_dir,
                                 profile.min_history_depth,
                                 profile.min_history_age_hours,
                                 to_runtime_key_storage(profile.key_storage)});
        if (auto save_res = runtime::save_profiles(config_path, profiles);
            !save_res) {
            return rollback_failure(ProfileErrorCode::ConfigFailure,
                                    save_res.error().detail);
        }

        return {};
    };

    auto result = do_create();

    wipe_credentials(credentials);
    if (master_key_res) {
        crypto::secure_memory::wipe(master_key_res->data(),
                                    master_key_res->size());
    }

    return result;
}

struct ScopedProfileLock {
    std::intptr_t handle = -1;
    ScopedProfileLock() = default;
    explicit ScopedProfileLock(std::intptr_t value) noexcept
        : handle(value) {}
    ScopedProfileLock(const ScopedProfileLock&) = delete;
    ScopedProfileLock& operator=(const ScopedProfileLock&) = delete;
    ScopedProfileLock(ScopedProfileLock&& other) noexcept
        : handle(std::exchange(other.handle, -1)) {}
    ScopedProfileLock& operator=(ScopedProfileLock&& other) noexcept {
        if (this != &other) {
            if (handle >= 0) {
                platform::release_profile_lock(handle);
            }
            handle = std::exchange(other.handle, -1);
        }
        return *this;
    }
    ~ScopedProfileLock() noexcept {
        if (handle >= 0) {
            platform::release_profile_lock(handle);
        }
    }
};

std::expected<ScopedProfileLock, ProfileError>
acquire_target_profile_lock(const std::filesystem::path& app_data_dir,
                            std::string_view profile_name) {
    const auto lock_path =
        app_data_dir / ("profile-" + std::string(profile_name) + ".lock");
    auto profile_lock = platform::acquire_profile_lock(lock_path);
    if (!profile_lock) {
        return fail_profile(ProfileErrorCode::LockFailure,
                            profile_lock.error());
    }
    return ScopedProfileLock{*profile_lock};
}

std::expected<void, ProfileError>
update_profile(const ExecutionEnvironment& environment, Profile profile) {
    if (!valid_retention_policy(profile)) {
        return fail_profile(ProfileErrorCode::ConfigFailure,
                            "invalid retention policy");
    }
    if (const auto valid = validate_profile_locations(profile); !valid) {
        return valid;
    }

    auto loaded = load_profiles_locked(environment.app_data_dir);
    if (!loaded) {
        return std::unexpected(loaded.error());
    }

    auto it = find_profile(loaded->profiles, profile.name);
    if (it == loaded->profiles.end()) {
        return fail_profile(ProfileErrorCode::NotFound, "profile not found");
    }

    const auto old_storage = it->key_storage;
    const auto new_storage = to_runtime_key_storage(profile.key_storage);
    auto profile_lock =
        acquire_target_profile_lock(environment.app_data_dir, profile.name);
    if (!profile_lock) {
        return std::unexpected(profile_lock.error());
    }

    it->local_dir = profile.local_dir;
    it->remote_dir = profile.remote_dir;
    it->min_history_depth = profile.min_history_depth;
    it->min_history_age_hours = profile.min_history_age_hours;
    it->key_storage = new_storage;

    auto save_res =
        runtime::save_profiles(loaded->config_path, loaded->profiles);
    if (!save_res) {
        return std::unexpected(map_runtime_error(save_res.error()));
    }

    if (old_storage != new_storage) {
        if (auto paths_res = runtime::resolve_profile_paths(
                environment.app_data_dir, profile.name)) {
            if (old_storage == runtime::KeyStorage::Vault) {
                static_cast<void>(
                    runtime::vault::delete_vault(paths_res->key_path));
            } else if (old_storage == runtime::KeyStorage::File) {
                std::error_code ec;
                const auto st =
                    std::filesystem::symlink_status(paths_res->key_path, ec);
                if (!ec && !std::filesystem::is_symlink(st) &&
                    std::filesystem::is_regular_file(st)) {
                    std::filesystem::remove(paths_res->key_path, ec);
                }
            }
        }
    }

    return {};
}

std::expected<void, ProfileError>
set_profile_key(const ExecutionEnvironment& environment,
                std::string_view profile_name,
                ProfileCredentials credentials) {
    std::expected<runtime::vault::KeyBytes, runtime::Error> master_key_res =
        std::unexpected(runtime::Error{.code = runtime::ErrorCode::KeyInvalid,
                                       .detail = "uninitialized"});

    auto do_set = [&]() -> std::expected<void, ProfileError> {
        if (!runtime::is_valid_profile_name(profile_name)) {
            return fail_profile(ProfileErrorCode::InvalidName,
                                "invalid profile name");
        }
        master_key_res = resolve_profile_credentials(credentials);
        if (!master_key_res) {
            return std::unexpected(map_runtime_error(master_key_res.error()));
        }
        auto loaded = load_profiles_locked(environment.app_data_dir);
        if (!loaded) {
            return std::unexpected(loaded.error());
        }
        const auto it = find_profile(loaded->profiles, profile_name);
        if (it == loaded->profiles.end()) {
            return fail_profile(ProfileErrorCode::NotFound,
                                "profile not found");
        }
        if (it->key_storage == runtime::KeyStorage::Memory) {
            return fail_profile(
                ProfileErrorCode::ConfigFailure,
                "profile uses 'memory' key_storage and does not persist keys");
        }
        auto paths_res = runtime::resolve_profile_paths(
            environment.app_data_dir, profile_name);
        if (!paths_res) {
            return std::unexpected(map_runtime_error(paths_res.error()));
        }
        const auto lock_path =
            environment.app_data_dir /
            ("profile-" + std::string(profile_name) + ".lock");
        auto profile_lock = platform::acquire_profile_lock(lock_path);
        if (!profile_lock) {
            return fail_profile(ProfileErrorCode::LockFailure,
                                profile_lock.error());
        }
        struct LockGuard {
            std::intptr_t handle;
            ~LockGuard() noexcept {
                platform::release_profile_lock(handle);
            }
        } lock_guard{*profile_lock};

        if (auto ensure_res = runtime::ensure_profile_directory(*paths_res);
            !ensure_res) {
            return std::unexpected(map_runtime_error(ensure_res.error()));
        }
        std::expected<void, runtime::Error> write_res;
        if (it->key_storage == runtime::KeyStorage::Vault) {
            write_res = runtime::vault::write_vault(paths_res->key_path,
                                                    *master_key_res);
        } else {
            write_res =
                runtime::vault::write(paths_res->key_path, *master_key_res);
        }
        if (!write_res) {
            return std::unexpected(map_runtime_error(write_res.error()));
        }
        return {};
    };

    auto result = do_set();
    wipe_credentials(credentials);
    if (master_key_res) {
        crypto::secure_memory::wipe(master_key_res->data(),
                                    master_key_res->size());
    }
    return result;
}

std::expected<void, ProfileError>
delete_profile(const ExecutionEnvironment& environment,
               std::string_view profile_name) {
    auto loaded = load_profiles_locked(environment.app_data_dir);
    if (!loaded) {
        return std::unexpected(loaded.error());
    }

    auto it = find_profile(loaded->profiles, profile_name);
    if (it == loaded->profiles.end()) {
        return fail_profile(ProfileErrorCode::NotFound, "profile not found");
    }

    auto profile_lock =
        acquire_target_profile_lock(environment.app_data_dir, profile_name);
    if (!profile_lock) {
        return std::unexpected(profile_lock.error());
    }

    auto original_profiles = loaded->profiles;
    loaded->profiles.erase(it);

    auto save_res =
        runtime::save_profiles(loaded->config_path, loaded->profiles);
    if (!save_res) {
        return std::unexpected(map_runtime_error(save_res.error()));
    }

    auto paths_res =
        runtime::resolve_profile_paths(environment.app_data_dir, profile_name);
    if (paths_res) {
        auto remove_res = runtime::remove_profile_directory(*paths_res);
        if (!remove_res) {
            auto rollback_res =
                runtime::save_profiles(loaded->config_path, original_profiles);
            std::string detail = remove_res.error().detail;
            if (!rollback_res) {
                detail +=
                    " (config rollback failed: " + rollback_res.error().detail +
                    ")";
            }
            return fail_profile(ProfileErrorCode::StorageFailure, detail);
        }
    }

    return {};
}

std::expected<void, ProfileError>
rename_profile(const ExecutionEnvironment& environment,
               std::string_view current_name,
               std::string_view new_name) {
    if (!runtime::is_valid_profile_name(new_name)) {
        return fail_profile(ProfileErrorCode::InvalidName,
                            "invalid profile name");
    }

    auto loaded = load_profiles_locked(environment.app_data_dir);
    if (!loaded) {
        return std::unexpected(loaded.error());
    }

    auto it_current = find_profile(loaded->profiles, current_name);
    if (it_current == loaded->profiles.end()) {
        return fail_profile(ProfileErrorCode::NotFound, "profile not found");
    }

    if (new_name == current_name ||
        find_profile_name_conflict(loaded->profiles, new_name, current_name) !=
            loaded->profiles.end()) {
        return fail_profile(ProfileErrorCode::AlreadyExists,
                            "a profile with this name already exists");
    }

    const bool case_only = runtime::fold_profile_name(current_name) ==
                           runtime::fold_profile_name(new_name);
    const auto first_lock_name =
        current_name <= new_name ? current_name : new_name;
    const auto second_lock_name =
        current_name <= new_name ? new_name : current_name;
    auto first_lock = acquire_target_profile_lock(
        environment.app_data_dir, first_lock_name);
    if (!first_lock) {
        return std::unexpected(first_lock.error());
    }
    ScopedProfileLock second_lock;
    std::error_code ec;
    const auto lock_path = [&](std::string_view name) {
        return environment.app_data_dir /
               ("profile-" + std::string{name} + ".lock");
    };
    const auto second_lock_path = lock_path(second_lock_name);
    if (!case_only ||
        platform::private_storage::is_reparse_or_symlink(second_lock_path) ||
        !std::filesystem::equivalent(
            lock_path(first_lock_name), second_lock_path, ec)) {
        auto second = acquire_target_profile_lock(
            environment.app_data_dir, second_lock_name);
        if (!second) {
            return std::unexpected(second.error());
        }
        second_lock = std::move(*second);
    }

    auto old_paths_res =
        runtime::resolve_profile_paths(environment.app_data_dir, current_name);
    auto new_paths_res =
        runtime::resolve_profile_paths(environment.app_data_dir, new_name);

    if (!old_paths_res || !new_paths_res) {
        return fail_profile(ProfileErrorCode::StorageFailure,
                            "failed to resolve paths");
    }

    const auto destination = query_entry(new_paths_res->profile_dir);
    if (destination.state != EntryState::Absent &&
        !(case_only && destination.is_plain_dir() &&
          std::filesystem::equivalent(
              old_paths_res->profile_dir, new_paths_res->profile_dir, ec))) {
        return fail_profile(ProfileErrorCode::StorageFailure,
                            "physical destination already exists");
    }

    bool phys_renamed = false;
    const auto old_status =
        std::filesystem::symlink_status(old_paths_res->profile_dir, ec);
    if (ec && !path_missing(ec)) {
        return fail_profile(ProfileErrorCode::StorageFailure, ec.message());
    }
    if (!ec && old_status.type() != std::filesystem::file_type::not_found) {
        auto ren_res =
            runtime::rename_profile_directory(*old_paths_res, *new_paths_res);
        if (!ren_res) {
            return std::unexpected(map_runtime_error(ren_res.error()));
        }
        phys_renamed = true;
    }

    bool vault_copied = false;
    const auto rollback_rename_phys = [&](std::string& detail) {
        if (vault_copied) {
            if (auto rb_vault =
                    runtime::vault::delete_vault(new_paths_res->key_path);
                !rb_vault) {
                detail +=
                    " (vault rollback failed: " + rb_vault.error().detail + ")";
            }
        }
        if (phys_renamed) {
            auto rb_res = runtime::rename_profile_directory(*new_paths_res,
                                                            *old_paths_res);
            if (!rb_res) {
                detail +=
                    " (directory rollback failed: " + rb_res.error().detail +
                    ")";
            }
        }
    };
    if (it_current->key_storage == runtime::KeyStorage::Vault
#if defined(_WIN32)
        && !case_only // Credential Manager keys use the same folded name.
#endif
    ) {
        auto vault_key = runtime::vault::read_vault(old_paths_res->key_path);
        if (vault_key) {
            KeyBytesWiper key_wiper{*vault_key};
            if (auto write_res = runtime::vault::write_vault(
                    new_paths_res->key_path, *vault_key);
                !write_res) {
                std::string detail = write_res.error().detail;
                rollback_rename_phys(detail);
                return fail_profile(ProfileErrorCode::StorageFailure, detail);
            }
            vault_copied = true;
        } else if (vault_key.error().code != runtime::ErrorCode::KeyNotFound) {
            std::string detail = vault_key.error().detail;
            rollback_rename_phys(detail);
            return fail_profile(ProfileErrorCode::CredentialFailure, detail);
        }
    }

    it_current->name = std::string(new_name);

    auto save_res =
        runtime::save_profiles(loaded->config_path, loaded->profiles);
    if (!save_res) {
        std::string detail = save_res.error().detail;
        rollback_rename_phys(detail);
        return fail_profile(ProfileErrorCode::StorageFailure, detail);
    }

    if (vault_copied) {
        static_cast<void>(
            runtime::vault::delete_vault(old_paths_res->key_path));
    }

    return {};
}

std::expected<void, ProfileError>
clone_profile(const ExecutionEnvironment& environment,
              std::string_view source_profile_name,
              std::string_view destination_profile_name) {
    if (!runtime::is_valid_profile_name(destination_profile_name)) {
        return fail_profile(ProfileErrorCode::InvalidName,
                            "invalid profile name");
    }

    auto loaded = load_profiles_locked(
        environment.app_data_dir, false, "source profile not found");
    if (!loaded) {
        return std::unexpected(loaded.error());
    }

    auto source_it = find_profile(loaded->profiles, source_profile_name);
    if (source_it == loaded->profiles.end()) {
        return fail_profile(ProfileErrorCode::NotFound,
                            "source profile not found");
    }

    if (find_profile_name_conflict(loaded->profiles,
                                   destination_profile_name) !=
        loaded->profiles.end()) {
        return fail_profile(ProfileErrorCode::AlreadyExists,
                            "a profile with this name already exists");
    }

    auto source_paths_res = runtime::resolve_profile_paths(
        environment.app_data_dir, source_profile_name);
    if (!source_paths_res) {
        return std::unexpected(map_runtime_error(source_paths_res.error()));
    }

    auto dest_paths_res = runtime::resolve_profile_paths(
        environment.app_data_dir, destination_profile_name);
    if (!dest_paths_res) {
        return std::unexpected(map_runtime_error(dest_paths_res.error()));
    }

    if (query_entry(dest_paths_res->profile_dir).state != EntryState::Absent) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail =
                "destination profile infrastructure already exists on disk",
        });
    }

    std::optional<runtime::vault::KeyBytes> master_key;
    struct OptionalKeyWiper {
        std::optional<runtime::vault::KeyBytes>& key;
        void release() noexcept {
            if (key) {
                crypto::secure_memory::wipe(key->data(), key->size());
                key.reset();
            }
        }
        ~OptionalKeyWiper() {
            release();
        }
    } key_wiper{master_key};

    if (source_it->key_storage == runtime::KeyStorage::File) {
        auto master_key_res =
            runtime::vault::read_only(source_paths_res->key_path);
        if (!master_key_res) {
            return std::unexpected(map_runtime_error(master_key_res.error()));
        }
        master_key = *master_key_res;
        crypto::secure_memory::wipe(master_key_res->data(),
                                    master_key_res->size());
    } else if (source_it->key_storage == runtime::KeyStorage::Vault) {
        auto master_key_res =
            runtime::vault::read_vault(source_paths_res->key_path);
        if (!master_key_res) {
            return std::unexpected(map_runtime_error(master_key_res.error()));
        }
        master_key = *master_key_res;
        crypto::secure_memory::wipe(master_key_res->data(),
                                    master_key_res->size());
    }

    for (const auto& directory : {environment.app_data_dir,
                                  dest_paths_res->profile_dir.parent_path()}) {
        auto ensure_res =
            platform::private_storage::ensure_directory(directory);
        if (!ensure_res) {
            return fail_profile(ProfileErrorCode::StorageFailure,
                                ensure_res.error());
        }
    }
    auto created = platform::private_storage::create_directory(
        dest_paths_res->profile_dir);
    if (!created) {
        return fail_profile(ProfileErrorCode::StorageFailure, created.error());
    }
    const auto clone_identity =
        query_directory_identity(dest_paths_res->profile_dir);
    using OwnedFile = platform::private_storage::PrivateOutputFile;
    using FileIdentity = platform::private_storage::FileIdentity;
    std::vector<std::pair<std::filesystem::path, FileIdentity>> clone_files;
    auto remember_clone_file = [&](const std::filesystem::path& path,
                                   bool required) {
        const auto info = query_entry(path);
        if (info.state == EntryState::Absent) {
            return !required;
        }
        if (!info.is_plain_file()) {
            return false;
        }
        const auto identity =
            platform::private_storage::query_file_identity(path);
        if (!identity.valid) {
            return false;
        }
        clone_files.emplace_back(path, identity);
        return true;
    };
    auto rollback_directory = [&]() -> std::expected<void, std::string> {
        const auto dir_info = query_entry(dest_paths_res->profile_dir);
        if (dir_info.state == EntryState::Absent) {
            return {};
        }
        if (dir_info.state != EntryState::Present || !clone_identity.valid ||
            !dir_info.directory || dir_info.link ||
            !(query_directory_identity(dest_paths_res->profile_dir) ==
              clone_identity)) {
            return std::unexpected("destination directory ownership changed");
        }
        std::vector<OwnedFile> files;
        std::error_code error;
        std::filesystem::directory_iterator entry(dest_paths_res->profile_dir,
                                                  error);
        const std::filesystem::directory_iterator end;
        while (!error && entry != end) {
            const auto path = entry->path();
            const auto name = path.filename();
            const bool known = name == "key.bin" || name == "db.sqlite" ||
                               name == "db.sqlite-wal" ||
                               name == "db.sqlite-shm" ||
                               name == "db.sqlite-journal";
            const auto info = query_entry(path);
            if (!known || !info.is_plain_file()) {
                return std::unexpected("destination contains unknown data");
            }
            const auto owned =
                std::ranges::find_if(clone_files, [&](const auto& candidate) {
                    return candidate.first == path;
                });
            const auto current_identity =
                platform::private_storage::query_file_identity(path);
            if (owned == clone_files.end() || !current_identity.valid ||
                !(current_identity == owned->second)) {
                return std::unexpected("destination file ownership changed");
            }
            files.push_back(OwnedFile{
                .path = path,
                .identity = current_identity,
            });
            entry.increment(error);
        }
        if (error || !(query_directory_identity(dest_paths_res->profile_dir) ==
                       clone_identity)) {
            return std::unexpected("could not verify destination directory");
        }
        for (auto& file : files) {
            // shortcut: POSIX unlink/rmdir are name-based; broker cleanup if
            // same-UID races enter scope.
            const auto result =
                platform::private_storage::remove_private_file_if_owned(file);
            if (result ==
                platform::private_storage::CleanupResult::IdentityMismatch) {
                return std::unexpected("destination file ownership changed");
            }
            if (result ==
                platform::private_storage::CleanupResult::AccessDenied) {
                return std::unexpected(
                    "access denied removing owned destination file");
            }
            if (result != platform::private_storage::CleanupResult::Removed &&
                result !=
                    platform::private_storage::CleanupResult::AlreadyAbsent) {
                return std::unexpected(
                    "failed to remove owned destination file");
            }
        }
#if defined(_WIN32)
        const auto directory = CreateFileW(
            dest_paths_res->profile_dir.c_str(),
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (directory == INVALID_HANDLE_VALUE) {
            return std::unexpected(
                "could not open destination directory for rollback");
        }
        FILE_ID_INFO directory_id{};
        FILE_ATTRIBUTE_TAG_INFO directory_attributes{};
        bool directory_verified =
            GetFileInformationByHandleEx(
                directory, FileIdInfo, &directory_id, sizeof(directory_id)) &&
            GetFileInformationByHandleEx(directory,
                                         FileAttributeTagInfo,
                                         &directory_attributes,
                                         sizeof(directory_attributes)) &&
            (directory_attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) !=
                0 &&
            (directory_attributes.FileAttributes &
             FILE_ATTRIBUTE_REPARSE_POINT) == 0;
        if (directory_verified) {
            std::uint64_t id_low = 0;
            std::uint64_t id_high = 0;
            std::memcpy(
                &id_low, directory_id.FileId.Identifier, sizeof(id_low));
            std::memcpy(&id_high,
                        directory_id.FileId.Identifier + sizeof(id_low),
                        sizeof(id_high));
            directory_verified = directory_id.VolumeSerialNumber ==
                                     clone_identity.volume_or_dev &&
                                 id_low == clone_identity.file_id_low &&
                                 id_high == clone_identity.file_id_high;
        }
        if (!directory_verified) {
            CloseHandle(directory);
            return std::unexpected("destination directory ownership changed");
        }
        FILE_DISPOSITION_INFO disposition{TRUE};
        const bool removed = SetFileInformationByHandle(
            directory, FileDispositionInfo, &disposition, sizeof(disposition));
        CloseHandle(directory);
        if (!removed) {
            return std::unexpected(
                "failed to remove owned destination directory");
        }
#else
        if (!(query_directory_identity(dest_paths_res->profile_dir) ==
              clone_identity) ||
            has_reparse_point(dest_paths_res->profile_dir)) {
            return std::unexpected("destination directory ownership changed");
        }
        std::filesystem::remove(dest_paths_res->profile_dir, error);
        if (error) {
            return std::unexpected(error.message());
        }
#endif
        const auto remaining =
            std::filesystem::symlink_status(dest_paths_res->profile_dir, error);
        if (error == std::errc::no_such_file_or_directory ||
            (!error &&
             remaining.type() == std::filesystem::file_type::not_found)) {
            return {};
        }
        return std::unexpected(error ? error.message()
                                     : "destination directory remains");
    };
    if (!clone_identity.valid) {
        return fail_profile(
            ProfileErrorCode::StorageFailure,
            "could not verify ownership of destination directory");
    }

    bool vault_written = false;
    const auto fail_with_rollback = [&](std::string detail) {
        if (vault_written) {
            if (auto vault_rb =
                    runtime::vault::delete_vault(dest_paths_res->key_path);
                !vault_rb) {
                detail +=
                    "; vault rollback also failed: " + vault_rb.error().detail;
            }
        }
        if (auto remove_res = rollback_directory(); !remove_res) {
            detail += "; rollback also failed: " + remove_res.error();
        }
        return fail_profile(ProfileErrorCode::StorageFailure,
                            std::move(detail));
    };

    bool write_ok = false;
    FileIdentity key_identity;
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_clone_fault_stage ==
        fault_test::CloneFaultStage::FailKeyWrite) {
        if (fault_test::g_clone_fault_observer) {
            fault_test::g_clone_fault_observer(
                fault_test::CloneFaultStage::FailKeyWrite);
        }
        write_ok = false;
    } else
#endif
    {
        if (source_it->key_storage == runtime::KeyStorage::File) {
            auto write_res = runtime::vault::write_new(
                dest_paths_res->key_path, *master_key, key_identity);
            write_ok = write_res.has_value();
            if (key_identity.valid) {
                clone_files.emplace_back(dest_paths_res->key_path,
                                         key_identity);
            }
            write_ok = write_ok && key_identity.valid;
        } else if (source_it->key_storage == runtime::KeyStorage::Vault) {
            auto write_res = runtime::vault::write_vault(
                dest_paths_res->key_path, *master_key);
            write_ok = write_res.has_value();
            vault_written = write_ok;
        } else {
            write_ok = true;
        }
    }
    key_wiper.release();
    if (!write_ok) {
        return fail_with_rollback(source_it->key_storage ==
                                              runtime::KeyStorage::File &&
                                          !key_identity.valid
                                      ? "failed to save or verify cloned key"
                                      : "failed to save vault");
    }

    bool db_ok = false;
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_clone_fault_stage ==
        fault_test::CloneFaultStage::FailDatabaseInit) {
        if (fault_test::g_clone_fault_observer) {
            fault_test::g_clone_fault_observer(
                fault_test::CloneFaultStage::FailDatabaseInit);
        }
        db_ok = false;
    } else
#endif
    {
        db_ok = state_storage::initialize(dest_paths_res->database_path);
    }
    const auto sidecars =
        detail::sqlite_sidecar_paths(dest_paths_res->database_path);
    const bool database_files_owned =
        db_ok && remember_clone_file(dest_paths_res->database_path, true) &&
        remember_clone_file(sidecars[0], false) &&
        remember_clone_file(sidecars[1], false) &&
        remember_clone_file(sidecars[2], false);
    if (!database_files_owned) {
        return fail_with_rollback("failed to initialize profile database");
    }

    auto cloned_profile = *source_it;
    cloned_profile.name = std::string(destination_profile_name);
    loaded->profiles.push_back(std::move(cloned_profile));

    std::expected<void, runtime::Error> save_res;
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_clone_fault_stage ==
        fault_test::CloneFaultStage::FailConfigSave) {
        if (fault_test::g_clone_fault_observer) {
            fault_test::g_clone_fault_observer(
                fault_test::CloneFaultStage::FailConfigSave);
        }
        save_res = std::unexpected(runtime::Error{
            runtime::ErrorCode::IoFailure, "injected config save failure"});
    } else if (fault_test::g_clone_fault_stage ==
               fault_test::CloneFaultStage::FailRollbackRemove) {
        save_res = std::unexpected(runtime::Error{
            runtime::ErrorCode::IoFailure, "injected config save failure"});
    } else
#endif
    {
        save_res =
            runtime::save_profiles(loaded->config_path, loaded->profiles);
    }

    if (!save_res) {
        std::string detail = save_res.error().detail;
        std::expected<void, runtime::Error> remove_res;
#ifdef KASUMI_MUTATION_FAULT_TESTS
        if (fault_test::g_clone_fault_stage ==
            fault_test::CloneFaultStage::FailRollbackRemove) {
            if (fault_test::g_clone_fault_observer) {
                fault_test::g_clone_fault_observer(
                    fault_test::CloneFaultStage::FailRollbackRemove);
            }
            remove_res = std::unexpected(
                runtime::Error{runtime::ErrorCode::IoFailure,
                               "injected rollback deletion failure"});
        } else
#endif
        {
            auto rollback_res = rollback_directory();
            if (!rollback_res) {
                remove_res = std::unexpected(runtime::Error{
                    runtime::ErrorCode::IoFailure, rollback_res.error()});
            }
        }
        if (!remove_res) {
            detail += "; rollback also failed: " + remove_res.error().detail;
        }
        if (vault_written) {
            if (auto vault_rb =
                    runtime::vault::delete_vault(dest_paths_res->key_path);
                !vault_rb) {
                detail +=
                    "; vault rollback also failed: " + vault_rb.error().detail;
            }
        }
        return fail_profile(ProfileErrorCode::ConfigFailure, detail);
    }

    return {};
}

ProfileLocalState
inspect_profile_local_state(const ExecutionEnvironment& environment,
                            std::string_view profile_name,
                            ProfileLocalProblem* problem) {
    if (problem) {
        *problem = ProfileLocalProblem::None;
    }
    const auto fail_inspection = [&](ProfileLocalProblem reason) {
        if (problem) {
            *problem = reason;
        }
        return ProfileLocalState::Problem;
    };
    if (!runtime::is_valid_profile_name(profile_name)) {
        return fail_inspection(ProfileLocalProblem::InvalidName);
    }

    auto paths =
        runtime::resolve_profile_paths(environment.app_data_dir, profile_name);
    if (!paths) {
        return fail_inspection(ProfileLocalProblem::Paths);
    }

    const auto profiles_dir = paths->profile_dir.parent_path();
    for (const auto& directory :
         {environment.app_data_dir, profiles_dir, paths->profile_dir}) {
        const auto entry = query_entry(directory);
        if (!entry.is_plain_dir()) {
            return fail_inspection(ProfileLocalProblem::Directory);
        }
    }

    runtime::KeyStorage key_storage = runtime::KeyStorage::File;
    if (auto loaded_profile = runtime::load_profile(
            environment.app_data_dir / "config.toml", profile_name)) {
        key_storage = loaded_profile->key_storage;
    }

    std::optional<runtime::vault::KeyBytes> key_bytes;
    struct OptionalKeyWiper {
        std::optional<runtime::vault::KeyBytes>& key;
        ~OptionalKeyWiper() noexcept {
            if (key) {
                crypto::secure_memory::wipe(key->data(), key->size());
            }
        }
    } key_wiper{key_bytes};

    if (key_storage == runtime::KeyStorage::File) {
        const auto key = query_entry(paths->key_path);
        if (!key.is_plain_file() || key.size != crypto::KEY_SIZE) {
            return fail_inspection(ProfileLocalProblem::Key);
        }
        auto read_res = runtime::vault::read_only(paths->key_path);
        if (!read_res) {
            return fail_inspection(ProfileLocalProblem::Key);
        }
        key_bytes = *read_res;
        crypto::secure_memory::wipe(read_res->data(), read_res->size());
    } else if (key_storage == runtime::KeyStorage::Vault) {
        auto read_res = runtime::vault::read_vault(paths->key_path);
        if (!read_res) {
            return fail_inspection(ProfileLocalProblem::Key);
        }
        key_bytes = *read_res;
        crypto::secure_memory::wipe(read_res->data(), read_res->size());
    }

    const auto database = query_entry(paths->database_path);
    if (!database.is_plain_file()) {
        return fail_inspection(ProfileLocalProblem::Database);
    }

    const auto lock_path = environment.app_data_dir /
                           ("profile-" + std::string(profile_name) + ".lock");
    if (probe_profile_lock(lock_path) != LockProbe::Inactive) {
        return fail_inspection(ProfileLocalProblem::Lock);
    }

    const auto auxiliary_corrupt = [](const auto& entry) {
        return entry.state == EntryState::Error ||
               (entry.state == EntryState::Present &&
                (!entry.regular || entry.link));
    };
    const auto sidecars = detail::sqlite_sidecar_paths(paths->database_path);
    const auto& rollback_path = sidecars[2];
    const auto rollback_corrupt = [&](const auto& entry) {
        return auxiliary_corrupt(entry) ||
               (entry.state == EntryState::Present && entry.size > 0 &&
                !can_read_first_byte(rollback_path));
    };

    const auto wal = query_entry(sidecars[0]);
    if (auxiliary_corrupt(wal)) {
        return fail_inspection(ProfileLocalProblem::Sidecar);
    }
    if (auxiliary_corrupt(query_entry(sidecars[1]))) {
        return fail_inspection(ProfileLocalProblem::Sidecar);
    }
    const auto rollback = query_entry(rollback_path);
    if (rollback_corrupt(rollback)) {
        return fail_inspection(ProfileLocalProblem::Sidecar);
    }

    auto journal_paths = sync::journal::make_paths(paths->profile_dir);
    if (!journal_paths) {
        return fail_inspection(ProfileLocalProblem::Journal);
    }
    const auto inspect_journal = [&]() {
        if (key_bytes) {
            return sync::journal::inspect(*journal_paths, *key_bytes);
        }
        const auto active_dir =
            query_entry(journal_paths->final_path.parent_path());
        const auto retired_dir =
            query_entry(paths->profile_dir / "transaction.bin.enc.cleared");
        if (active_dir.state == EntryState::Error ||
            retired_dir.state == EntryState::Error) {
            return sync::journal::InspectionResult::Corrupted;
        }
        if ((active_dir.state == EntryState::Present &&
             !active_dir.is_plain_dir()) ||
            (retired_dir.state == EntryState::Present &&
             !retired_dir.is_plain_dir()) ||
            (active_dir.state == EntryState::Present &&
             retired_dir.state == EntryState::Present)) {
            return sync::journal::InspectionResult::Corrupted;
        }
        if (active_dir.state == EntryState::Absent &&
            retired_dir.state == EntryState::Absent) {
            return sync::journal::InspectionResult::Absent;
        }
        if (retired_dir.state == EntryState::Present) {
            return sync::journal::InspectionResult::Retired;
        }
        const auto retired_marker = query_entry(
            journal_paths->final_path.parent_path() / "retired.enc");
        if (retired_marker.state == EntryState::Error ||
            (retired_marker.state == EntryState::Present &&
             !retired_marker.is_plain_file())) {
            return sync::journal::InspectionResult::Corrupted;
        }
        return retired_marker.state == EntryState::Present
                   ? sync::journal::InspectionResult::Retired
                   : sync::journal::InspectionResult::Active;
    };
    const auto journal = inspect_journal();
    if (journal == sync::journal::InspectionResult::Corrupted) {
        return fail_inspection(ProfileLocalProblem::Journal);
    }
    const bool active_journal =
        journal == sync::journal::InspectionResult::Active;
    bool active_rollback_journal =
        rollback.state == EntryState::Present && rollback.size > 0;

    auto random_id = platform::random::hex_id(16);
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
        fault_test::InspectFaultStage::FailRandomId) {
        random_id = std::unexpected("injected random id failure");
    }
#endif
    if (!random_id || random_id->empty()) {
        return fail_inspection(ProfileLocalProblem::Workspace);
    }

    std::error_code temp_error;
    const auto temp_root = std::filesystem::temp_directory_path(temp_error);
    if (temp_error) {
        return fail_inspection(ProfileLocalProblem::Workspace);
    }

    std::filesystem::path candidate;
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
        fault_test::InspectFaultStage::SimulateTempDirCollision) {
        candidate = fault_test::g_inspect_fault_path.empty()
                        ? temp_root / "kasumi_insp_collision_test_dir"
                        : fault_test::g_inspect_fault_path;
    } else {
        candidate = temp_root / ("kasumi_insp_" + *random_id);
    }
#else
    candidate = temp_root / ("kasumi_insp_" + *random_id);
#endif
    if (query_entry(candidate).state != EntryState::Absent) {
        return fail_inspection(ProfileLocalProblem::Workspace);
    }
    if (!platform::private_storage::create_directory(candidate)) {
        return fail_inspection(ProfileLocalProblem::Workspace);
    }
    InspectionTempDirectory temporary{candidate};
    temporary.owns = true;
    temporary.identity = query_directory_identity(candidate);
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::FailDirectoryIdentity &&
        !fault_test::g_inspect_identity_failure_consumed) {
        fault_test::g_inspect_identity_failure_consumed = true;
        temporary.identity = {};
    }
#endif
    if (!temporary.identity.valid) {
        return fail_inspection(ProfileLocalProblem::Workspace);
    }
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_observer &&
        fault_test::g_inspect_fault_stage !=
            fault_test::InspectFaultStage::ConcurrentSnapshotBarrier) {
        fault_test::g_inspect_fault_observer(fault_test::g_inspect_fault_stage);
    }
#endif
    {
        const auto entry = query_entry(candidate);
        if (!entry.is_plain_dir() ||
            !(query_directory_identity(candidate) == temporary.identity)) {
            return fail_inspection(ProfileLocalProblem::Workspace);
        }
    }

#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::FailSnapshot ||
        fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::FailSqliteCopy) {
        return fail_inspection(ProfileLocalProblem::Snapshot);
    }
#endif

    const auto copy_path = candidate / "db.sqlite";
    if (query_entry(copy_path).state != EntryState::Absent) {
        return fail_inspection(ProfileLocalProblem::Snapshot);
    }
    if (!take_sqlite_snapshot(paths->database_path,
                              copy_path,
                              wal.state == EntryState::Present,
                              active_rollback_journal)) {
        return fail_inspection(ProfileLocalProblem::Snapshot);
    }

#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
        fault_test::InspectFaultStage::SimulateConcurrentModification) {
        return fail_inspection(ProfileLocalProblem::Snapshot);
    }
#endif

    auto loaded = state_storage::load_state(copy_path);
    if (!loaded.has_value()) {
        return fail_inspection(ProfileLocalProblem::Database);
    }

    const auto final_journal = inspect_journal();
    if (final_journal == sync::journal::InspectionResult::Corrupted) {
        return fail_inspection(ProfileLocalProblem::Journal);
    }
    const auto final_rollback = query_entry(rollback_path);
    if (rollback_corrupt(final_rollback)) {
        return fail_inspection(ProfileLocalProblem::Sidecar);
    }
    active_rollback_journal = active_rollback_journal ||
                              (final_rollback.state == EntryState::Present &&
                               final_rollback.size > 0);

    if (!temporary.perform_cleanup()) {
        return fail_inspection(ProfileLocalProblem::Cleanup);
    }

    if (active_journal || active_rollback_journal ||
        final_journal == sync::journal::InspectionResult::Active) {
        return ProfileLocalState::Pending;
    }
    if (!loaded->has_value()) {
        return ProfileLocalState::Initialized;
    }
    if (!(*loaded)->pending_materializations.empty()) {
        return ProfileLocalState::Pending;
    }
    return ProfileLocalState::Ready;
}

std::string_view to_string(ProfileLocalState state) noexcept {
    switch (state) {
        case ProfileLocalState::Initialized:
            return "Initialized";
        case ProfileLocalState::Ready:
            return "Ready";
        case ProfileLocalState::Pending:
            return "Pending";
        case ProfileLocalState::Problem:
            return "Problem";
    }
    return "Problem";
}

namespace {

ProfileOperationKind
to_profile_op(state_storage::LocalOperationKind kind) noexcept {
    using SK = state_storage::LocalOperationKind;
    using PK = ProfileOperationKind;
    switch (kind) {
        case SK::Sync:
            return PK::Sync;
        case SK::Fsck:
            return PK::Fsck;
        case SK::GarbageCollect:
            return PK::GarbageCollect;
        case SK::Repack:
            return PK::Repack;
        case SK::ResolveMissing:
            return PK::ResolveMissing;
        case SK::RemoveWriter:
            return PK::RemoveWriter;
        case SK::RemoveBarrier:
            return PK::RemoveBarrier;
    }
    return PK::Sync;
}

ProfileExecutionStatus
to_profile_status(state_storage::LocalExecutionStatus status,
                  bool lock_held) noexcept {
    using SS = state_storage::LocalExecutionStatus;
    using PS = ProfileExecutionStatus;
    switch (status) {
        case SS::InProgress:
            return lock_held ? PS::InProgress : PS::Interrupted;
        case SS::Succeeded:
            return PS::Succeeded;
        case SS::SucceededNoChanges:
            return PS::SucceededNoChanges;
        case SS::SucceededDownloadedOnly:
            return PS::SucceededDownloadedOnly;
        case SS::Partial:
            return PS::SucceededPartial;
        case SS::IssuesFound:
            return PS::IssuesFound;
        case SS::Blocked:
            return PS::Blocked;
        case SS::Cancelled:
            return PS::Cancelled;
        case SS::Failed:
            return PS::Failed;
        case SS::Uncertain:
            return PS::Uncertain;
    }
    return PS::Failed;
}

ProfileRemotePublishState
to_profile_publish(state_storage::RemotePublishState state) noexcept {
    using SP = state_storage::RemotePublishState;
    using PP = ProfileRemotePublishState;
    switch (state) {
        case SP::NotApplicable:
            return PP::NotApplicable;
        case SP::Published:
            return PP::Published;
        case SP::Pending:
            return PP::Pending;
    }
    return PP::NotApplicable;
}

} // namespace

ProfileActivityReport
inspect_profile_activity(const ExecutionEnvironment& environment,
                         std::string_view profile_name) {
    ProfileActivityReport report;
    if (!runtime::is_valid_profile_name(profile_name)) {
        return report;
    }
    auto paths =
        runtime::resolve_profile_paths(environment.app_data_dir, profile_name);
    if (!paths) {
        return report;
    }
    const auto profiles_dir = paths->profile_dir.parent_path();
    for (const auto& directory :
         {environment.app_data_dir, profiles_dir, paths->profile_dir}) {
        if (!query_entry(directory).is_plain_dir()) {
            return report;
        }
    }
    const auto db_entry = query_entry(paths->database_path);
    if (!db_entry.is_plain_file()) {
        return report;
    }
    const auto auxiliary_corrupt = [](const EntryInfo& entry) {
        return entry.state == EntryState::Error ||
               (entry.state == EntryState::Present &&
                (!entry.regular || entry.link));
    };
    const auto sidecars = detail::sqlite_sidecar_paths(paths->database_path);
    const auto wal = query_entry(sidecars[0]);
    const auto shm = query_entry(sidecars[1]);
    const auto rollback = query_entry(sidecars[2]);
    if (auxiliary_corrupt(wal) || auxiliary_corrupt(shm) ||
        auxiliary_corrupt(rollback)) {
        return report;
    }

    // Always snapshot db.sqlite to a temporary directory before opening with
    // SQLite so read-only queries never touch WAL/SHM sidecars or DB mtimes.
    auto random_id = platform::random::hex_id(16);
    std::error_code temp_error;
    const auto temp_root = std::filesystem::temp_directory_path(temp_error);
    if (!random_id || random_id->empty() || temp_error) {
        return report;
    }
    const auto temp_dir = temp_root / ("kasumi_act_" + *random_id);
    if (!platform::private_storage::create_directory(temp_dir)) {
        return report;
    }
    InspectionTempDirectory guard{temp_dir};
    guard.owns = true;
    guard.identity = query_directory_identity(temp_dir);
    if (!guard.identity.valid) {
        return report;
    }
    const auto copy_path = temp_dir / "db.sqlite";
    const bool active_rollback =
        rollback.state == EntryState::Present && rollback.size > 0;
    if (!take_sqlite_snapshot(paths->database_path,
                              copy_path,
                              wal.state == EntryState::Present,
                              active_rollback)) {
        return report;
    }
    auto loaded_activity = state_storage::load_local_activity(copy_path);
    static_cast<void>(guard.perform_cleanup());
    if (!loaded_activity) {
        return report;
    }

    report.database_present = true;
    const auto lock_path = environment.app_data_dir /
                           ("profile-" + std::string{profile_name} + ".lock");
    const bool lock_held = platform::is_profile_lock_held(lock_path);

    if (loaded_activity->accepted_commit) {
        const auto& meta = *loaded_activity->accepted_commit;
        report.accepted_commit = ProfileCommitAuthorship{
            .commit_id = meta.commit_id,
            .height = meta.height,
            .created_at = meta.created_at,
            .origin_operation = static_cast<std::uint8_t>(meta.origin_operation),
            .machine_id_hex = meta.machine_id_hex,
            .machine_name = meta.machine_name,
            .accepted_at = meta.accepted_at,
        };
    }

    report.recent_executions.reserve(loaded_activity->executions.size());
    for (const auto& rec : loaded_activity->executions) {
        ProfileExecutionSummary item{
            .execution_id = rec.execution_id,
            .operation = to_profile_op(rec.operation),
            .machine_id_hex = rec.machine_id_hex,
            .machine_name = rec.machine_name,
            .started_at = rec.started_at,
            .finished_at = rec.finished_at,
            .duration_ms = rec.duration_ms,
            .status = to_profile_status(rec.status, lock_held),
            .recovered = rec.recovered,
            .stage = rec.stage,
            .detail = rec.detail,
            .commit_id = rec.commit_id,
            .summary_a = rec.summary_a,
            .summary_b = rec.summary_b,
            .summary_c = rec.summary_c,
            .summary_bytes = rec.summary_bytes,
            .flags = rec.flags,
            .remote_publish_state =
                to_profile_publish(rec.remote_publish_state),
        };
        if (!report.last_attempt) {
            report.last_attempt = item;
        }
        if (!report.last_complete_sync &&
            item.operation == ProfileOperationKind::Sync &&
            (item.status == ProfileExecutionStatus::Succeeded ||
             item.status == ProfileExecutionStatus::SucceededNoChanges ||
             item.status == ProfileExecutionStatus::SucceededDownloadedOnly)) {
            report.last_complete_sync = item;
        }
        report.recent_executions.push_back(std::move(item));
    }

    report.cached_remote_activities.reserve(
        loaded_activity->cached_remote_activities.size());
    for (const auto& entry : loaded_activity->cached_remote_activities) {
        report.cached_remote_activities.push_back(ProfileCachedRemoteActivity{
            .event_id = entry.event_id,
            .operation = entry.operation,
            .outcome = entry.outcome,
            .machine_id_hex = entry.machine_id_hex,
            .machine_name = entry.machine_name,
            .started_at = entry.started_at,
            .finished_at = entry.finished_at,
            .duration_ms = entry.duration_ms,
            .metric_primary = entry.metric_primary,
            .metric_secondary = entry.metric_secondary,
            .metric_bytes = entry.metric_bytes,
            .flags = entry.flags,
            .stage = entry.stage,
            .detail = entry.detail,
            .cached_at = entry.cached_at,
        });
    }
    return report;
}

} // namespace kasumi::application
