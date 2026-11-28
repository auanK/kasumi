#include "application/profile.hpp"
#ifdef KASUMI_MUTATION_FAULT_TESTS
#include "application/sync/mutation_fault_test.hpp"
#endif
#include "core/ignore.hpp"
#include "core/node.hpp"
#include "platform/durability.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/profile_lock.hpp"
#include "platform/random.hpp"
#include "runtime/profile.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace kasumi::application {
namespace {

bool is_link_or_reparse(const std::filesystem::path& path,
                        const std::filesystem::file_status& status) noexcept {
    if (std::filesystem::is_symlink(status)) {
        return true;
    }
#if defined(_WIN32)
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES &&
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return true;
    }
#else
    static_cast<void>(path);
#endif
    return false;
}

bool is_digits(std::string_view value) noexcept {
    return !value.empty() && std::ranges::all_of(value, [](char ch) {
        return ch >= '0' && ch <= '9';
    });
}

bool is_lower_hex_12(std::string_view value) noexcept {
    return value.size() == 12U && std::ranges::all_of(value, [](char ch) {
               return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
           });
}

struct ParsedConflictName {
    std::string canonical_path;
    ConflictOrigin origin = ConflictOrigin::Local;
    std::string origin_tag;
};

std::optional<ParsedConflictName>
parse_conflict_logical_path(std::string_view logical_path) {
    constexpr std::string_view kMarker = ".kasumiconflict_";
    const auto slash = logical_path.rfind('/');
    const auto base_start = slash == std::string_view::npos ? 0U : slash + 1U;
    const auto filename = logical_path.substr(base_start);
    const auto pos = filename.rfind(kMarker);
    if (pos == std::string_view::npos || pos == 0U) {
        return std::nullopt;
    }

    const auto canonical = logical_path.substr(0U, base_start + pos);
    const auto suffix = filename.substr(pos + kMarker.size());
    if (suffix.empty()) {
        return std::nullopt;
    }

    const auto dot = suffix.find('.');
    const auto head =
        dot == std::string_view::npos ? suffix : suffix.substr(0U, dot);
    const auto tail = dot == std::string_view::npos ? std::string_view{}
                                                    : suffix.substr(dot + 1U);
    if (dot != std::string_view::npos && !is_digits(tail)) {
        return std::nullopt;
    }

    if (head == "local") {
        return ParsedConflictName{
            .canonical_path = std::string{canonical},
            .origin = ConflictOrigin::Local,
            .origin_tag = "local",
        };
    }
    if (head == "remote") {
        return ParsedConflictName{
            .canonical_path = std::string{canonical},
            .origin = ConflictOrigin::Remote,
            .origin_tag = "remote",
        };
    }
    if (is_lower_hex_12(head)) {
        return ParsedConflictName{
            .canonical_path = std::string{canonical},
            .origin = ConflictOrigin::BranchCommit,
            .origin_tag = std::string{head},
        };
    }
    return std::nullopt;
}

std::int64_t read_mtime_unix_seconds(const std::filesystem::path& path) {
    const auto mtime = platform::metadata::last_write_time(path);
    if (!mtime) {
        return 0;
    }
    const auto ns = platform::metadata::unix_nanoseconds(*mtime);
    if (!ns) {
        return 0;
    }
    constexpr std::int64_t kNsPerSec = 1000000000LL;
    return *ns >= 0 ? *ns / kNsPerSec : (*ns - (kNsPerSec - 1LL)) / kNsPerSec;
}

} // namespace

std::expected<LocalConflictsReport, ProfileError>
list_local_conflicts(const ExecutionEnvironment& environment,
                     std::string_view profile_name) {
    if (!runtime::is_valid_profile_name(profile_name)) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::InvalidName,
            .detail = "invalid profile name",
        });
    }

    auto profiles = list_profiles(environment);
    if (!profiles) {
        return std::unexpected(profiles.error());
    }
    const auto it = std::ranges::find(*profiles, profile_name, &Profile::name);
    if (it == profiles->end()) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::NotFound,
            .detail = "profile not found",
        });
    }

    const auto& local_dir = it->local_dir;
    std::error_code fs_ec;
    const auto root_status = std::filesystem::symlink_status(local_dir, fs_ec);
    if (fs_ec || is_link_or_reparse(local_dir, root_status) ||
        !std::filesystem::is_directory(root_status)) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = "profile local directory is missing or inaccessible",
        });
    }

    kasumi::ignore::IgnoreList ignore_list;
    std::filesystem::path ignore_file_path;
    for (const auto& entry : std::filesystem::directory_iterator(
             local_dir,
             std::filesystem::directory_options::skip_permission_denied,
             fs_ec)) {
        const auto name_utf8 =
            platform::path::to_logical_utf8(entry.path().filename());
        if (kasumi::ignore::is_kasumiignore_path(name_utf8)) {
            ignore_file_path = entry.path();
            break;
        }
    }
    fs_ec.clear();
    if (!ignore_file_path.empty()) {
        const auto ignore_status =
            std::filesystem::symlink_status(ignore_file_path, fs_ec);
        if (!fs_ec && !is_link_or_reparse(ignore_file_path, ignore_status) &&
            std::filesystem::is_regular_file(ignore_status)) {
            ignore_list = kasumi::ignore::load_ignore_list(ignore_file_path);
            if (ignore_list.parse_error) {
                return std::unexpected(ProfileError{
                    .code = ProfileErrorCode::ConfigFailure,
                    .detail = ".kasumiignore parse error: " +
                              ignore_list.parse_error->detail,
                });
            }
        }
    }

    std::map<std::string, std::vector<LocalConflictArtifact>> grouped;
    struct WalkFrame {
        std::filesystem::directory_iterator it;
        std::string rel_prefix;
    };
    std::vector<WalkFrame> stack;
    {
        std::error_code dir_ec;
        std::filesystem::directory_iterator root_it(
            local_dir,
            std::filesystem::directory_options::skip_permission_denied,
            dir_ec);
        if (dir_ec) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure,
                .detail = "failed to scan local directory: " + dir_ec.message(),
            });
        }
        stack.push_back(WalkFrame{.it = std::move(root_it), .rel_prefix = {}});
    }

    while (!stack.empty()) {
        auto& frame = stack.back();
        if (frame.it == std::filesystem::directory_iterator{}) {
            stack.pop_back();
            continue;
        }

        const auto entry_path = frame.it->path();
        const auto entry_name =
            platform::path::to_logical_utf8(entry_path.filename());
        std::error_code inc_ec;
        frame.it.increment(inc_ec);
        if (inc_ec) {
            stack.pop_back();
            continue;
        }

        const auto rel_path = frame.rel_prefix.empty()
                                  ? entry_name
                                  : frame.rel_prefix + "/" + entry_name;
        std::error_code st_ec;
        const auto status = std::filesystem::symlink_status(entry_path, st_ec);
        if (st_ec || is_link_or_reparse(entry_path, status)) {
            continue;
        }

        const bool is_dir = std::filesystem::is_directory(status);
        const bool is_file = std::filesystem::is_regular_file(status);
        if (!is_dir && !is_file) {
            continue;
        }
        if (kasumi::ignore::is_reserved_internal(rel_path) ||
            kasumi::ignore::is_ignored(rel_path, ignore_list, is_dir)) {
            continue;
        }

        if (is_dir) {
            std::error_code sub_ec;
            std::filesystem::directory_iterator sub_it(
                entry_path,
                std::filesystem::directory_options::skip_permission_denied,
                sub_ec);
            if (!sub_ec) {
                stack.push_back(
                    WalkFrame{.it = std::move(sub_it), .rel_prefix = rel_path});
            }
            continue;
        }

        const auto parsed = parse_conflict_logical_path(rel_path);
        if (!parsed) {
            continue;
        }
        std::error_code size_ec;
        const auto file_size = std::filesystem::file_size(entry_path, size_ec);
        grouped[parsed->canonical_path].push_back(LocalConflictArtifact{
            .path = rel_path,
            .origin = parsed->origin,
            .origin_tag = parsed->origin_tag,
            .size = size_ec ? 0ULL : static_cast<std::uint64_t>(file_size),
            .modified_at = read_mtime_unix_seconds(entry_path),
        });
    }

    LocalConflictsReport report{
        .profile_name = it->name,
        .local_dir = local_dir,
    };
    report.groups.reserve(grouped.size());
    for (auto& [canonical_path, artifacts] : grouped) {
        std::ranges::sort(artifacts, {}, &LocalConflictArtifact::path);
        report.total_artifacts += artifacts.size();

        LocalConflictGroup group{
            .canonical_path = canonical_path,
            .artifacts = std::move(artifacts),
        };
        const auto canonical_fs =
            local_dir / platform::path::from_utf8(canonical_path);
        std::error_code can_ec;
        const auto can_status =
            std::filesystem::symlink_status(canonical_fs, can_ec);
        if (!can_ec && !is_link_or_reparse(canonical_fs, can_status) &&
            std::filesystem::is_regular_file(can_status)) {
            group.canonical_exists = true;
            std::error_code sz_ec;
            const auto sz = std::filesystem::file_size(canonical_fs, sz_ec);
            group.canonical_size =
                sz_ec ? 0ULL : static_cast<std::uint64_t>(sz);
            group.canonical_modified_at = read_mtime_unix_seconds(canonical_fs);
        }
        report.groups.push_back(std::move(group));
    }
    return report;
}

namespace {

bool verify_relative_parent_dirs(const std::filesystem::path& local_dir,
                                 std::string_view canonical_path) {
    std::filesystem::path cur = local_dir;
    std::size_t start = 0;
    while (true) {
        const auto slash = canonical_path.find('/', start);
        if (slash == std::string_view::npos) {
            break;
        }
        cur /= platform::path::from_utf8(
            canonical_path.substr(start, slash - start));
        std::error_code ec;
        const auto st = std::filesystem::symlink_status(cur, ec);
        if (ec || is_link_or_reparse(cur, st) ||
            !std::filesystem::is_directory(st)) {
            return false;
        }
        start = slash + 1U;
    }
    return true;
}

bool matches_artifact_selector(const LocalConflictGroup& group,
                               const LocalConflictArtifact& artifact,
                               std::string_view selector) {
    if (artifact.path == selector) {
        return true;
    }
    const auto slash = artifact.path.rfind('/');
    const auto filename =
        slash == std::string::npos
            ? std::string_view{artifact.path}
            : std::string_view{artifact.path}.substr(slash + 1U);
    if (filename == selector) {
        return true;
    }
    const std::string prefix = group.canonical_path + ".kasumiconflict_";
    return artifact.path.starts_with(prefix) &&
           std::string_view{artifact.path}.substr(prefix.size()) == selector;
}

} // namespace

std::expected<ResolveConflictReport, ProfileError>
resolve_local_conflict(const ExecutionEnvironment& environment,
                       const ResolveConflictRequest& request) {
    if (!runtime::is_valid_profile_name(request.profile_name)) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::InvalidName,
            .detail = "invalid profile name",
        });
    }
    if (!kasumi::valid_logical_path(request.canonical_path)) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::InvalidPath,
            .detail = "invalid conflict canonical path",
        });
    }
    if (request.choice == ConflictResolutionChoice::KeepArtifact &&
        request.artifact_selector.empty()) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::InvalidPath,
            .detail = "artifact selector cannot be empty",
        });
    }

    struct ScopedProfileLock {
        std::intptr_t handle = platform::invalid_profile_lock;
        ~ScopedProfileLock() {
            platform::release_profile_lock(handle);
        }
    } lock_guard;

    if (!request.dry_run) {
        std::error_code dir_ec;
        std::filesystem::create_directories(environment.app_data_dir, dir_ec);
        const auto lock_path = environment.app_data_dir /
                               ("profile-" + request.profile_name + ".lock");
        auto acquired = platform::acquire_profile_lock(lock_path);
        if (!acquired) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::LockFailure,
                .detail =
                    "profile is currently in use by another Kasumi process",
            });
        }
        lock_guard.handle = *acquired;
    }

    auto listed = list_local_conflicts(environment, request.profile_name);
    if (!listed) {
        return std::unexpected(listed.error());
    }

    const auto group_it =
        std::ranges::find(listed->groups,
                          request.canonical_path,
                          &LocalConflictGroup::canonical_path);
    if (group_it == listed->groups.end()) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::NotFound,
            .detail = "no conflict artifacts found for path",
        });
    }

    const auto& local_dir = listed->local_dir;
    if (!verify_relative_parent_dirs(local_dir, group_it->canonical_path)) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = "conflict parent directory is missing or redirected",
        });
    }

    const auto canonical_fs =
        local_dir / platform::path::from_utf8(group_it->canonical_path);
    std::error_code can_ec;
    const auto can_status =
        std::filesystem::symlink_status(canonical_fs, can_ec);
    const bool canonical_absent =
        can_ec == std::errc::no_such_file_or_directory;
    if (!canonical_absent &&
        (can_ec || is_link_or_reparse(canonical_fs, can_status) ||
         !std::filesystem::is_regular_file(can_status))) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = "canonical path is not a safe regular file",
        });
    }

    std::optional<std::string> selected_artifact;
    std::filesystem::path selected_fs;
    if (request.choice == ConflictResolutionChoice::KeepCanonical) {
        if (!group_it->canonical_exists || canonical_absent) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::InvalidPath,
                .detail =
                    "canonical file does not exist; select an artifact with "
                    "--keep",
            });
        }
    } else {
        std::vector<const LocalConflictArtifact*> matches;
        for (const auto& art : group_it->artifacts) {
            if (matches_artifact_selector(
                    *group_it, art, request.artifact_selector)) {
                matches.push_back(&art);
            }
        }
        if (matches.empty()) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::NotFound,
                .detail = "requested conflict artifact was not found",
            });
        }
        if (matches.size() > 1U) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::InvalidPath,
                .detail =
                    "artifact selector matched multiple conflict artifacts; "
                    "specify the full artifact path or filename",
            });
        }
        selected_artifact = matches.front()->path;
        selected_fs = local_dir / platform::path::from_utf8(*selected_artifact);
    }

    namespace ps = platform::private_storage;
    namespace durability = platform::durability;
    struct Artifact {
        std::filesystem::path path;
        ps::FileIdentity identity;
    };
    std::vector<Artifact> artifacts;
    std::vector<std::string> removed_paths;
    for (const auto& art : group_it->artifacts) {
        auto path = local_dir / platform::path::from_utf8(art.path);
        const auto identity = ps::query_file_identity(path);
        if (!identity.valid) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure,
                .detail = "conflict artifact is missing or not a regular file",
            });
        }
        artifacts.push_back({std::move(path), identity});
        removed_paths.push_back(art.path);
    }

    ResolveConflictReport report{
        .profile_name = listed->profile_name,
        .canonical_path = group_it->canonical_path,
        .choice = request.choice,
        .selected_artifact = selected_artifact,
        .dry_run = request.dry_run,
        .removed_artifacts = std::move(removed_paths),
    };
    if (request.dry_run) {
        return report;
    }

    auto token = platform::random::hex_id();
    if (!token) {
        return std::unexpected(ProfileError{ProfileErrorCode::StorageFailure, token.error()});
    }
    const auto recovery = canonical_fs.parent_path() /
        (std::string(ignore::conflict_recovery_prefix) + *token);
    if (auto made = ps::create_directory(recovery); !made) {
        return std::unexpected(ProfileError{ProfileErrorCode::StorageFailure, made.error()});
    }
    const auto location = platform::path::to_logical_utf8(recovery.lexically_relative(local_dir));
    // Never touch an artifact name a second time unless rollback can claim
    // that name atomically. Editors may already have saved a replacement.
    std::size_t claimed = 0;
    auto rollback = [&](std::string detail) -> std::unexpected<ProfileError> {
        while (claimed != 0) {
            const auto& original = artifacts[--claimed].path;
            (void)durability::move_regular_file(recovery / original.filename(), original,
                                                durability::ExistingTarget::Reject);
        }
        std::error_code ec;
        std::filesystem::remove(recovery, ec);  // only succeeds if empty
        if (ec) detail += "; remaining originals in " + location;
        return std::unexpected(ProfileError{ProfileErrorCode::StorageFailure, std::move(detail)});
    };
    for (const auto& art : artifacts) {
        const auto saved = recovery / art.path.filename();
        if (auto moved = durability::move_regular_file(art.path, saved, durability::ExistingTarget::Reject);
            !moved) {
            return rollback("failed to reserve conflict artifact: " + moved.error());
        }
        ++claimed;
        if (ps::query_file_identity(saved) != art.identity) {
            return rollback("conflict artifact changed during resolution");
        }
    }
    const auto sync_directories = [&]() -> std::expected<void, std::string> {
        if (auto synced = durability::sync_parent_directory(recovery / artifacts.front().path.filename()); !synced) {
            return synced;
        }
        return durability::sync_parent_directory(recovery);
    };
    if (auto synced = sync_directories(); !synced) return rollback(synced.error());

#ifdef KASUMI_MUTATION_FAULT_TESTS
    sync::mutation_fault_test::hit("conflict_artifacts_reserved", recovery);
#endif
    if (!selected_artifact && !ps::query_file_identity(canonical_fs).valid) {
        return rollback("canonical file disappeared during resolution");
    }
    if (selected_artifact) {
        // Promote the original file object so open writers follow it.
        const auto saved = recovery / selected_fs.filename();
        if (auto moved = durability::move_regular_file(saved, canonical_fs,
                canonical_absent ? durability::ExistingTarget::Reject : durability::ExistingTarget::Replace);
            !moved) {
            return rollback("failed to promote conflict artifact: " + moved.error());
        }
        if (auto synced = sync_directories(); !synced) {
            return std::unexpected(ProfileError{ProfileErrorCode::StorageFailure,
                "promotion completed but directory flush failed: " + synced.error() + "; recovery: " + location});
        }
    }
    if (selected_artifact && artifacts.size() == 1) {
        std::error_code ec;
        std::filesystem::remove(recovery, ec);
        if (ec) report.recovery_directory = location;
    } else {
        report.recovery_directory = location;
    }
    return report;
}

} // namespace kasumi::application
