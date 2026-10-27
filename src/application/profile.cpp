#include "application/profile.hpp"
#include "application/profile_directory_identity.hpp"
#include "application/sync/journal.hpp"

#include "crypto/content.hpp"
#include "core/history.hpp"
#include "crypto/secure_memory.hpp"
#include "runtime/error.hpp"
#include "runtime/paths.hpp"
#include "runtime/profile.hpp"
#include "runtime/vault.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/profile_lock.hpp"
#include "platform/random.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"
#ifdef KASUMI_MUTATION_FAULT_TESTS
#include "application/profile_fault_test.hpp"
#endif

#include <algorithm>
#include <chrono>
#include <cstdint>
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

using detail::DirectoryIdentity;
using detail::has_reparse_point;
using detail::query_directory_identity;

bool valid_retention_policy(const Profile& profile) noexcept {
    return profile.min_history_depth > 0 &&
           profile.min_history_depth <= history::maximum_graph_depth &&
           profile.min_history_age_hours > 0;
}

ProfileError map_runtime_error(const runtime::Error& err) {
    ProfileErrorCode code = ProfileErrorCode::ConfigFailure;
    switch (err.code) {
        case runtime::ErrorCode::InvalidProfileName:
            code = ProfileErrorCode::InvalidName;
            break;
        case runtime::ErrorCode::ProfileNotFound:
            code = ProfileErrorCode::NotFound;
            break;
        case runtime::ErrorCode::KeyNotFound:
        case runtime::ErrorCode::KeyInvalid:
        case runtime::ErrorCode::KeyDerivationFailure:
        case runtime::ErrorCode::KeyWriteFailure:
            code = ProfileErrorCode::CredentialFailure;
            break;
        case runtime::ErrorCode::IoFailure:
        case runtime::ErrorCode::PathEscape:
            code = ProfileErrorCode::StorageFailure;
            break;
        case runtime::ErrorCode::ConfigNotFound:
        case runtime::ErrorCode::ConfigInvalid:
        case runtime::ErrorCode::ProfileInvalid:
            code = ProfileErrorCode::ConfigFailure;
            break;
    }
    return ProfileError{.code = code, .detail = err.detail};
}
class ScopedConfigLock {
public:
    static std::expected<ScopedConfigLock, ProfileError>
    acquire(const std::filesystem::path& app_data_dir,
            std::chrono::milliseconds timeout = std::chrono::milliseconds(500)) {
        auto secured = platform::private_storage::ensure_directory(app_data_dir);
        if (!secured) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure,
                .detail = secured.error(),
            });
        }
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
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::LockFailure,
            .detail = "could not acquire configuration lock: " + last_error,
        });
    }

    ~ScopedConfigLock() {
        platform::release_profile_lock(handle_);
    }

    ScopedConfigLock(const ScopedConfigLock&) = delete;
    ScopedConfigLock& operator=(const ScopedConfigLock&) = delete;

    ScopedConfigLock(ScopedConfigLock&& other) noexcept
        : handle_(std::exchange(other.handle_, platform::invalid_profile_lock)) {}

    ScopedConfigLock& operator=(ScopedConfigLock&& other) noexcept {
        if (this != &other) {
            platform::release_profile_lock(handle_);
            handle_ = std::exchange(other.handle_, platform::invalid_profile_lock);
        }
        return *this;
    }

private:
    explicit ScopedConfigLock(std::intptr_t handle) noexcept : handle_(handle) {}
    std::intptr_t handle_ = platform::invalid_profile_lock;
};

enum class EntryState { Absent, Present, Error };

struct EntryInfo {
    EntryState state = EntryState::Error;
    bool directory = false;
    bool regular = false;
    bool link = false;
    std::uintmax_t size = 0;
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
        (!error &&
         status.type() == std::filesystem::file_type::not_found)) {
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

enum class LockProbe { Inactive, Active, Error };

bool can_read_first_byte(const std::filesystem::path& path) {
#if defined(_WIN32)
    const HANDLE handle = CreateFileW(path.c_str(),
                                      GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE |
                                          FILE_SHARE_DELETE,
                                      nullptr,
                                      OPEN_EXISTING,
                                      FILE_FLAG_OPEN_REPARSE_POINT,
                                      nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    char byte = 0;
    DWORD read = 0;
    const bool result = ReadFile(handle, &byte, 1, &read, nullptr) && read == 1;
    CloseHandle(handle);
    return result;
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
        return false;
    }
    char byte = 0;
    const auto count = ::read(handle, &byte, 1);
    static_cast<void>(::close(handle));
    return count == 1;
#endif
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
        : path(value) {}

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
            const bool known = name == "db.sqlite" ||
                               name == "db.sqlite-wal" ||
                               name == "db.sqlite-shm" ||
                               name == "db.sqlite-journal";
            const auto info = query_entry(entry->path());
            if (info.state != EntryState::Present || !info.regular ||
                info.link || !known) {
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
    const auto handle = CreateFileW(path.c_str(),
                                    FILE_READ_ATTRIBUTES,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE |
                                        FILE_SHARE_DELETE,
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
    struct stat status {};
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
    auto wal_source = source;
    wal_source += "-wal";
    auto rollback_source = source;
    rollback_source += "-journal";
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
    std::optional<SnapshotFileState> wal_before;
    std::optional<SnapshotFileState> rollback_before;
    if (wal.state == EntryState::Present) {
        wal_before = snapshot_file_state(wal_source);
        if (!wal_before) {
            return false;
        }
    }
    if (rollback.state == EntryState::Present && rollback.size > 0) {
        rollback_before = snapshot_file_state(rollback_source);
        if (!rollback_before) {
            return false;
        }
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
    if (wal_before) {
        auto wal_destination = destination;
        wal_destination += "-wal";
        error.clear();
        if (!std::filesystem::copy_file(
                wal_source, wal_destination, error) || error) {
            return false;
        }
    }
    if (rollback_before) {
        auto rollback_destination = destination;
        rollback_destination += "-journal";
        error.clear();
        if (!std::filesystem::copy_file(
                rollback_source, rollback_destination, error) || error) {
            return false;
        }
    }
    const auto database_after = snapshot_file_state(source);
    if (!database_after || *database_after != *database_before) {
        return false;
    }
    if (wal_before) {
        const auto state = snapshot_file_state(wal_source);
        if (!state || *state != *wal_before) {
            return false;
        }
    }
    if (rollback_before) {
        const auto state = snapshot_file_state(rollback_source);
        if (!state || *state != *rollback_before) {
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
} // namespace

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
                    .min_history_age_hours = p.min_history_age_hours});
    }
    return result;
}

std::expected<void, ProfileError>
create_profile(const ExecutionEnvironment& environment,
               Profile profile,
               ProfileCredentials credentials) {
    auto lock = ScopedConfigLock::acquire(environment.app_data_dir);
    if (!lock) {
        wipe_credentials(credentials);
        return std::unexpected(lock.error());
    }
    std::expected<runtime::vault::KeyBytes, runtime::Error> master_key_res =
        std::unexpected(runtime::Error{.code = runtime::ErrorCode::KeyInvalid,
                                       .detail = "uninitialized"});

    auto do_create = [&]() -> std::expected<void, ProfileError> {
        if (!runtime::is_valid_profile_name(profile.name)) {
            return std::unexpected(
                ProfileError{.code = ProfileErrorCode::InvalidName,
                             .detail = "invalid profile name"});
        }
        if (!valid_retention_policy(profile)) {
            return std::unexpected(
                ProfileError{.code = ProfileErrorCode::ConfigFailure,
                             .detail = "invalid retention policy"});
        }
        if (!profile.local_dir.is_absolute()) {
            return std::unexpected(
                ProfileError{.code = ProfileErrorCode::StorageFailure,
                             .detail = "local path must be absolute"});
        }

        const auto valid_storage =
            transport::validate_transport_location(profile.remote_dir);
        if (!valid_storage) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure,
                .detail = transport::describe(valid_storage.error()),
            });
        }

        if (const auto* hex = std::get_if<MasterKeyHex>(&credentials)) {
            master_key_res = runtime::vault::decode_hex(hex->value);
        } else if (const auto* pair = std::get_if<PasswordPair>(&credentials)) {
            master_key_res =
                runtime::vault::derive(pair->password, pair->salt_password);
        }

        if (!master_key_res) {
            return std::unexpected(map_runtime_error(master_key_res.error()));
        }

        auto config_path = environment.app_data_dir / "config.toml";
        auto profiles_res = runtime::load_profiles(config_path);
        std::vector<runtime::ProfileData> profiles;
        if (!profiles_res) {
            if (profiles_res.error().code !=
                runtime::ErrorCode::ConfigNotFound) {
                return std::unexpected(map_runtime_error(profiles_res.error()));
            }
        } else {
            profiles = std::move(*profiles_res);
        }

        auto it = std::ranges::find_if(profiles, [&](const auto& p) {
            return p.name == profile.name;
        });
        if (it != profiles.end()) {
            return std::unexpected(
                ProfileError{.code = ProfileErrorCode::AlreadyExists,
                             .detail = "profile already exists"});
        }

        auto paths_res = runtime::resolve_profile_paths(
            environment.app_data_dir, profile.name);
        if (!paths_res) {
            return std::unexpected(map_runtime_error(paths_res.error()));
        }

        std::error_code ec;
        if (std::filesystem::exists(paths_res->profile_dir, ec) ||
            std::filesystem::exists(paths_res->key_path, ec)) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure,
                .detail = "profile infrastructure already exists on disk"});
        }

        auto ensure_res = runtime::ensure_profile_directory(*paths_res);
        if (!ensure_res) {
            return std::unexpected(map_runtime_error(ensure_res.error()));
        }

        if (!runtime::vault::write(paths_res->key_path, *master_key_res)) {
            auto remove_res = runtime::remove_profile_directory(*paths_res);
            std::string detail = "failed to save vault";
            if (!remove_res) {
                detail += "; rollback also failed: " + remove_res.error().detail;
            }
            return std::unexpected(
                ProfileError{.code = ProfileErrorCode::StorageFailure,
                             .detail = detail});
        }

        if (!state_storage::initialize(paths_res->database_path)) {
            auto remove_res = runtime::remove_profile_directory(*paths_res);
            std::string detail = "failed to initialize profile database";
            if (!remove_res) {
                detail += "; rollback also failed: " + remove_res.error().detail;
            }
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure,
                .detail = detail});
        }

        profiles.push_back(runtime::ProfileData{profile.name,
                                                profile.local_dir,
                                                profile.remote_dir,
                                                profile.min_history_depth,
                                                profile.min_history_age_hours});
        auto save_res = runtime::save_profiles(config_path, profiles);
        if (!save_res) {
            std::string detail = save_res.error().detail;
            auto remove_res = runtime::remove_profile_directory(*paths_res);
            if (!remove_res) {
                detail += "; rollback also failed: " + remove_res.error().detail;
            }
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::ConfigFailure,
                .detail = detail});
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

std::expected<void, ProfileError>
update_profile(const ExecutionEnvironment& environment, Profile profile) {
    if (!profile.local_dir.is_absolute()) {
        return std::unexpected(
            ProfileError{.code = ProfileErrorCode::StorageFailure,
                         .detail = "local path must be absolute"});
    }
    const auto valid_storage =
        transport::validate_transport_location(profile.remote_dir);
    if (!valid_storage) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = transport::describe(valid_storage.error()),
        });
    }

    auto lock = ScopedConfigLock::acquire(environment.app_data_dir);
    if (!lock) {
        return std::unexpected(lock.error());
    }

    auto config_path = environment.app_data_dir / "config.toml";
    auto profiles_res = runtime::load_profiles(config_path);
    if (!profiles_res) {
        return std::unexpected(map_runtime_error(profiles_res.error()));
    }

    auto it = std::ranges::find_if(*profiles_res, [&](const auto& p) {
        return p.name == profile.name;
    });
    if (it == profiles_res->end()) {
        return std::unexpected(ProfileError{.code = ProfileErrorCode::NotFound,
                                            .detail = "profile not found"});
    }

    it->local_dir = profile.local_dir;
    it->remote_dir = profile.remote_dir;

    auto save_res = runtime::save_profiles(config_path, *profiles_res);
    if (!save_res) {
        return std::unexpected(map_runtime_error(save_res.error()));
    }

    return {};
}

std::expected<void, ProfileError>
delete_profile(const ExecutionEnvironment& environment,
               std::string_view profile_name) {
    auto lock = ScopedConfigLock::acquire(environment.app_data_dir);
    if (!lock) {
        return std::unexpected(lock.error());
    }

    auto config_path = environment.app_data_dir / "config.toml";
    auto profiles_res = runtime::load_profiles(config_path);
    if (!profiles_res) {
        return std::unexpected(map_runtime_error(profiles_res.error()));
    }

    auto it = std::ranges::find_if(*profiles_res, [&](const auto& p) {
        return p.name == profile_name;
    });
    if (it == profiles_res->end()) {
        return std::unexpected(ProfileError{.code = ProfileErrorCode::NotFound,
                                            .detail = "profile not found"});
    }

    auto original_profiles = *profiles_res;
    profiles_res->erase(it);

    auto save_res = runtime::save_profiles(config_path, *profiles_res);
    if (!save_res) {
        return std::unexpected(map_runtime_error(save_res.error()));
    }

    auto paths_res =
        runtime::resolve_profile_paths(environment.app_data_dir, profile_name);
    if (paths_res) {
        auto remove_res = runtime::remove_profile_directory(*paths_res);
        if (!remove_res) {
            auto rollback_res =
                runtime::save_profiles(config_path, original_profiles);
            std::string detail = remove_res.error().detail;
            if (!rollback_res) {
                detail +=
                    " (config rollback failed: " + rollback_res.error().detail +
                    ")";
            }
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure, .detail = detail});
        }
    }

    return {};
}

std::expected<void, ProfileError>
rename_profile(const ExecutionEnvironment& environment,
               std::string_view current_name,
               std::string_view new_name) {
    if (!runtime::is_valid_profile_name(new_name)) {
        return std::unexpected(
            ProfileError{.code = ProfileErrorCode::InvalidName,
                         .detail = "invalid profile name"});
    }

    auto lock = ScopedConfigLock::acquire(environment.app_data_dir);
    if (!lock) {
        return std::unexpected(lock.error());
    }

    auto config_path = environment.app_data_dir / "config.toml";
    auto profiles_res = runtime::load_profiles(config_path);
    if (!profiles_res) {
        return std::unexpected(map_runtime_error(profiles_res.error()));
    }

    auto it_current = std::ranges::find_if(*profiles_res, [&](const auto& p) {
        return p.name == current_name;
    });
    if (it_current == profiles_res->end()) {
        return std::unexpected(ProfileError{.code = ProfileErrorCode::NotFound,
                                            .detail = "profile not found"});
    }

    auto it_new = std::ranges::find_if(*profiles_res, [&](const auto& p) {
        return p.name == new_name;
    });
    if (it_new != profiles_res->end()) {
        return std::unexpected(
            ProfileError{.code = ProfileErrorCode::AlreadyExists,
                         .detail = "a profile with this name already exists"});
    }

    auto old_paths_res =
        runtime::resolve_profile_paths(environment.app_data_dir, current_name);
    auto new_paths_res =
        runtime::resolve_profile_paths(environment.app_data_dir, new_name);

    if (!old_paths_res || !new_paths_res) {
        return std::unexpected(
            ProfileError{.code = ProfileErrorCode::StorageFailure,
                         .detail = "failed to resolve paths"});
    }

    std::error_code ec;
    if (std::filesystem::exists(new_paths_res->profile_dir, ec)) {
        return std::unexpected(
            ProfileError{.code = ProfileErrorCode::StorageFailure,
                         .detail = "physical destination already exists"});
    }

    bool phys_renamed = false;
    if (std::filesystem::exists(old_paths_res->profile_dir, ec)) {
        auto ren_res =
            runtime::rename_profile_directory(*old_paths_res, *new_paths_res);
        if (!ren_res) {
            return std::unexpected(map_runtime_error(ren_res.error()));
        }
        phys_renamed = true;
    }

    it_current->name = std::string(new_name);

    auto save_res = runtime::save_profiles(config_path, *profiles_res);
    if (!save_res) {
        std::string detail = save_res.error().detail;
        if (phys_renamed) {
            auto rb_res = runtime::rename_profile_directory(*new_paths_res,
                                                            *old_paths_res);
            if (!rb_res) {
                detail +=
                    " (directory rollback failed: " + rb_res.error().detail +
                    ")";
            }
        }
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure, .detail = detail});
    }

    return {};
}



std::expected<void, ProfileError>
clone_profile(const ExecutionEnvironment& environment,
              std::string_view source_profile_name,
              std::string_view destination_profile_name) {
    if (!runtime::is_valid_profile_name(destination_profile_name)) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::InvalidName,
            .detail = "invalid profile name",
        });
    }

    auto lock = ScopedConfigLock::acquire(environment.app_data_dir);
    if (!lock) {
        return std::unexpected(lock.error());
    }

    auto config_path = environment.app_data_dir / "config.toml";
    auto profiles_res = runtime::load_profiles(config_path);
    if (!profiles_res) {
        if (profiles_res.error().code == runtime::ErrorCode::ConfigNotFound) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::NotFound,
                .detail = "source profile not found",
            });
        }
        return std::unexpected(map_runtime_error(profiles_res.error()));
    }

    auto source_it = std::ranges::find_if(*profiles_res, [&](const auto& p) {
        return p.name == source_profile_name;
    });
    if (source_it == profiles_res->end()) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::NotFound,
            .detail = "source profile not found",
        });
    }

    auto dest_it = std::ranges::find_if(*profiles_res, [&](const auto& p) {
        return p.name == destination_profile_name;
    });
    if (dest_it != profiles_res->end()) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::AlreadyExists,
            .detail = "a profile with this name already exists",
        });
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

    std::error_code ec;
    const auto dest_status =
        std::filesystem::symlink_status(dest_paths_res->profile_dir, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = "failed to inspect destination profile directory: " +
                      ec.message(),
        });
    }
    if (dest_status.type() != std::filesystem::file_type::not_found) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = "destination profile infrastructure already exists on disk",
        });
    }

    auto master_key_res = runtime::vault::read_only(source_paths_res->key_path);
    if (!master_key_res) {
        return std::unexpected(map_runtime_error(master_key_res.error()));
    }

    for (const auto& directory : {environment.app_data_dir,
                                  dest_paths_res->profile_dir.parent_path()}) {
        auto ensure_res = platform::private_storage::ensure_directory(directory);
        if (!ensure_res) {
            crypto::secure_memory::wipe(master_key_res->data(), master_key_res->size());
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure,
                .detail = ensure_res.error(),
            });
        }
    }
    auto created = platform::private_storage::create_directory(
        dest_paths_res->profile_dir);
    if (!created) {
        crypto::secure_memory::wipe(master_key_res->data(), master_key_res->size());
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = created.error(),
        });
    }
    const auto clone_identity =
        query_directory_identity(dest_paths_res->profile_dir);
    using OwnedFile = platform::private_storage::PrivateOutputFile;
    using FileIdentity = platform::private_storage::FileIdentity;
    std::vector<std::pair<std::filesystem::path, FileIdentity>> clone_files;
    auto remember_clone_file = [&](const std::filesystem::path& path,
                                   bool required) {
        std::error_code error;
        const auto file_status = std::filesystem::symlink_status(path, error);
        if (error == std::errc::no_such_file_or_directory ||
            (!error &&
             file_status.type() == std::filesystem::file_type::not_found)) {
            return !required;
        }
        if (error || !std::filesystem::is_regular_file(file_status) ||
            std::filesystem::is_symlink(file_status) ||
            has_reparse_point(path)) {
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
        std::error_code error;
        const auto status =
            std::filesystem::symlink_status(dest_paths_res->profile_dir, error);
        if (error == std::errc::no_such_file_or_directory ||
            (!error &&
             status.type() == std::filesystem::file_type::not_found)) {
            return {};
        }
        if (error || !clone_identity.valid ||
            !std::filesystem::is_directory(status) ||
            std::filesystem::is_symlink(status) ||
            has_reparse_point(dest_paths_res->profile_dir) ||
            !(query_directory_identity(dest_paths_res->profile_dir) ==
              clone_identity)) {
            return std::unexpected("destination directory ownership changed");
        }
        std::vector<OwnedFile> files;
        std::filesystem::directory_iterator entry(
            dest_paths_res->profile_dir, error);
        const std::filesystem::directory_iterator end;
        while (!error && entry != end) {
            const auto path = entry->path();
            const auto name = path.filename();
            const bool known = name == "key.bin" || name == "db.sqlite" ||
                               name == "db.sqlite-wal" ||
                               name == "db.sqlite-shm" ||
                               name == "db.sqlite-journal";
            const auto child_status = entry->symlink_status(error);
            if (error || !known ||
                !std::filesystem::is_regular_file(child_status) ||
                std::filesystem::is_symlink(child_status) ||
                has_reparse_point(path)) {
                return std::unexpected("destination contains unknown data");
            }
            const auto owned = std::ranges::find_if(
                clone_files, [&](const auto& candidate) {
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
        if (error ||
            !(query_directory_identity(dest_paths_res->profile_dir) ==
              clone_identity)) {
            return std::unexpected("could not verify destination directory");
        }
        for (auto& file : files) {
            // shortcut: POSIX unlink/rmdir are name-based; broker cleanup if same-UID races enter scope.
            const auto result =
                platform::private_storage::remove_private_file_if_owned(file);
            if (result == platform::private_storage::CleanupResult::IdentityMismatch) {
                return std::unexpected("destination file ownership changed");
            }
            if (result == platform::private_storage::CleanupResult::AccessDenied) {
                return std::unexpected("access denied removing owned destination file");
            }
            if (result != platform::private_storage::CleanupResult::Removed &&
                result != platform::private_storage::CleanupResult::AlreadyAbsent) {
                return std::unexpected("failed to remove owned destination file");
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
            return std::unexpected("could not open destination directory for rollback");
        }
        FILE_ID_INFO directory_id{};
        FILE_ATTRIBUTE_TAG_INFO directory_attributes{};
        const bool directory_verified =
            GetFileInformationByHandleEx(
                directory, FileIdInfo, &directory_id, sizeof(directory_id)) &&
            GetFileInformationByHandleEx(directory,
                                         FileAttributeTagInfo,
                                         &directory_attributes,
                                         sizeof(directory_attributes)) &&
            directory_id.VolumeSerialNumber == clone_identity.volume &&
            std::equal(clone_identity.identifier.begin(),
                       clone_identity.identifier.end(),
                       directory_id.FileId.Identifier) &&
            (directory_attributes.FileAttributes &
             FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (directory_attributes.FileAttributes &
             FILE_ATTRIBUTE_REPARSE_POINT) == 0;
        if (!directory_verified) {
            CloseHandle(directory);
            return std::unexpected("destination directory ownership changed");
        }
        FILE_DISPOSITION_INFO disposition{TRUE};
        const bool removed = SetFileInformationByHandle(directory,
                                                        FileDispositionInfo,
                                                        &disposition,
                                                        sizeof(disposition));
        CloseHandle(directory);
        if (!removed) {
            return std::unexpected("failed to remove owned destination directory");
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
        crypto::secure_memory::wipe(master_key_res->data(), master_key_res->size());
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = "could not verify ownership of destination directory",
        });
    }

    bool write_ok = false;
    FileIdentity key_identity;
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_clone_fault_stage == fault_test::CloneFaultStage::FailKeyWrite) {
        if (fault_test::g_clone_fault_observer) {
            fault_test::g_clone_fault_observer(fault_test::CloneFaultStage::FailKeyWrite);
        }
        write_ok = false;
    } else
#endif
    {
        auto write_res = runtime::vault::write_new(
            dest_paths_res->key_path, *master_key_res, key_identity);
        write_ok = write_res.has_value();
    }
    if (key_identity.valid) {
        clone_files.emplace_back(dest_paths_res->key_path, key_identity);
    }
    const bool key_owned = write_ok && key_identity.valid;
    crypto::secure_memory::wipe(master_key_res->data(), master_key_res->size());
    if (!write_ok || !key_owned) {
        auto remove_res = rollback_directory();
        std::string detail = write_ok ? "could not verify cloned key ownership"
                                      : "failed to save vault";
        if (!remove_res) {
            detail += "; rollback also failed: " + remove_res.error();
        }
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = detail,
        });
    }

    bool db_ok = false;
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_clone_fault_stage == fault_test::CloneFaultStage::FailDatabaseInit) {
        if (fault_test::g_clone_fault_observer) {
            fault_test::g_clone_fault_observer(fault_test::CloneFaultStage::FailDatabaseInit);
        }
        db_ok = false;
    } else
#endif
    {
        db_ok = state_storage::initialize(dest_paths_res->database_path);
    }
    auto wal_path = dest_paths_res->database_path;
    wal_path += "-wal";
    auto shm_path = dest_paths_res->database_path;
    shm_path += "-shm";
    auto rollback_path = dest_paths_res->database_path;
    rollback_path += "-journal";
    const bool database_files_owned =
        db_ok && remember_clone_file(dest_paths_res->database_path, true) &&
        remember_clone_file(wal_path, false) &&
        remember_clone_file(shm_path, false) &&
        remember_clone_file(rollback_path, false);
    if (!database_files_owned) {
        auto remove_res = rollback_directory();
        std::string detail = "failed to initialize profile database";
        if (!remove_res) {
            detail += "; rollback also failed: " + remove_res.error();
        }
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = detail,
        });
    }

    auto cloned_profile = *source_it;
    cloned_profile.name = std::string(destination_profile_name);
    profiles_res->push_back(std::move(cloned_profile));

    std::expected<void, runtime::Error> save_res;
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_clone_fault_stage == fault_test::CloneFaultStage::FailConfigSave) {
        if (fault_test::g_clone_fault_observer) {
            fault_test::g_clone_fault_observer(fault_test::CloneFaultStage::FailConfigSave);
        }
        save_res = std::unexpected(runtime::Error{runtime::ErrorCode::IoFailure, "injected config save failure"});
    } else if (fault_test::g_clone_fault_stage == fault_test::CloneFaultStage::FailRollbackRemove) {
        save_res = std::unexpected(runtime::Error{runtime::ErrorCode::IoFailure, "injected config save failure"});
    } else
#endif
    {
        save_res = runtime::save_profiles(config_path, *profiles_res);
    }

    if (!save_res) {
        std::string detail = save_res.error().detail;
        std::expected<void, runtime::Error> remove_res;
#ifdef KASUMI_MUTATION_FAULT_TESTS
        if (fault_test::g_clone_fault_stage == fault_test::CloneFaultStage::FailRollbackRemove) {
            if (fault_test::g_clone_fault_observer) {
                fault_test::g_clone_fault_observer(fault_test::CloneFaultStage::FailRollbackRemove);
            }
            remove_res = std::unexpected(runtime::Error{runtime::ErrorCode::IoFailure, "injected rollback deletion failure"});
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
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::ConfigFailure,
            .detail = detail,
        });
    }

    return {};
}

ProfileLocalState inspect_profile_local_state(
    const ExecutionEnvironment& environment,
    std::string_view profile_name) {
    if (!runtime::is_valid_profile_name(profile_name)) {
        return ProfileLocalState::Problem;
    }

    auto paths =
        runtime::resolve_profile_paths(environment.app_data_dir, profile_name);
    if (!paths) {
        return ProfileLocalState::Problem;
    }

    const auto profiles_dir = paths->profile_dir.parent_path();
    for (const auto& directory :
         {environment.app_data_dir, profiles_dir, paths->profile_dir}) {
        const auto entry = query_entry(directory);
        if (entry.state != EntryState::Present || !entry.directory ||
            entry.link) {
            return ProfileLocalState::Problem;
        }
    }

    const auto key = query_entry(paths->key_path);
    if (key.state != EntryState::Present || !key.regular || key.link ||
        key.size != crypto::KEY_SIZE) {
        return ProfileLocalState::Problem;
    }
    auto key_bytes = runtime::vault::read_only(paths->key_path);
    if (!key_bytes) {
        return ProfileLocalState::Problem;
    }

    const auto database = query_entry(paths->database_path);
    if (database.state != EntryState::Present || !database.regular ||
        database.link) {
        return ProfileLocalState::Problem;
    }

    const auto lock_path =
        environment.app_data_dir /
        ("profile-" + std::string(profile_name) + ".lock");
    if (probe_profile_lock(lock_path) != LockProbe::Inactive) {
        return ProfileLocalState::Problem;
    }

    const auto wal = query_entry(paths->profile_dir / "db.sqlite-wal");
    if (wal.state == EntryState::Error ||
        (wal.state == EntryState::Present && (!wal.regular || wal.link))) {
        return ProfileLocalState::Problem;
    }
    const auto shm = query_entry(paths->profile_dir / "db.sqlite-shm");
    if (shm.state == EntryState::Error ||
        (shm.state == EntryState::Present && (!shm.regular || shm.link))) {
        return ProfileLocalState::Problem;
    }
    const auto rollback = query_entry(paths->profile_dir / "db.sqlite-journal");
    if (rollback.state == EntryState::Error ||
        (rollback.state == EntryState::Present &&
         (!rollback.regular || rollback.link))) {
        return ProfileLocalState::Problem;
    }
    if (rollback.state == EntryState::Present && rollback.size > 0 &&
        !can_read_first_byte(paths->profile_dir / "db.sqlite-journal")) {
        return ProfileLocalState::Problem;
    }

    auto journal_paths = sync::journal::make_paths(paths->profile_dir);
    if (!journal_paths) {
        return ProfileLocalState::Problem;
    }
    const auto journal = sync::journal::inspect(*journal_paths, *key_bytes);
    if (journal == sync::journal::InspectionResult::Corrupted) {
        return ProfileLocalState::Problem;
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
        return ProfileLocalState::Problem;
    }

    std::error_code temp_error;
    const auto temp_root = std::filesystem::temp_directory_path(temp_error);
    if (temp_error) {
        return ProfileLocalState::Problem;
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
        return ProfileLocalState::Problem;
    }
    if (!platform::private_storage::create_directory(candidate)) {
        return ProfileLocalState::Problem;
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
        return ProfileLocalState::Problem;
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
        if (entry.state != EntryState::Present || !entry.directory ||
            entry.link ||
            !(query_directory_identity(candidate) == temporary.identity)) {
            return ProfileLocalState::Problem;
        }
    }

#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::FailSnapshot ||
        fault_test::g_inspect_fault_stage ==
            fault_test::InspectFaultStage::FailSqliteCopy) {
        return ProfileLocalState::Problem;
    }
#endif

    const auto copy_path = candidate / "db.sqlite";
    if (query_entry(copy_path).state != EntryState::Absent) {
        return ProfileLocalState::Problem;
    }
    if (!take_sqlite_snapshot(paths->database_path,
                              copy_path,
                              wal.state == EntryState::Present,
                              active_rollback_journal)) {
        return ProfileLocalState::Problem;
    }

#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (fault_test::g_inspect_fault_stage ==
        fault_test::InspectFaultStage::SimulateConcurrentModification) {
        return ProfileLocalState::Problem;
    }
#endif

    auto loaded = state_storage::load_state(copy_path);
    if (!loaded.has_value()) {
        return ProfileLocalState::Problem;
    }

    const auto final_journal =
        sync::journal::inspect(*journal_paths, *key_bytes);
    if (final_journal == sync::journal::InspectionResult::Corrupted) {
        return ProfileLocalState::Problem;
    }
    const auto final_rollback =
        query_entry(paths->profile_dir / "db.sqlite-journal");
    if (final_rollback.state == EntryState::Error ||
        (final_rollback.state == EntryState::Present &&
         (!final_rollback.regular || final_rollback.link)) ||
        (final_rollback.state == EntryState::Present &&
         final_rollback.size > 0 &&
         !can_read_first_byte(paths->profile_dir / "db.sqlite-journal"))) {
        return ProfileLocalState::Problem;
    }
    active_rollback_journal =
        active_rollback_journal ||
        (final_rollback.state == EntryState::Present &&
         final_rollback.size > 0);

    if (!temporary.perform_cleanup()) {
        return ProfileLocalState::Problem;
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
        case ProfileLocalState::Initialized: return "Initialized";
        case ProfileLocalState::Ready: return "Ready";
        case ProfileLocalState::Pending: return "Pending";
        case ProfileLocalState::Problem: return "Problem";
    }
    return "Problem";
}

} // namespace kasumi::application
