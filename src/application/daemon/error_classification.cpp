#include "application/daemon/error_classification.hpp"

#include "application/daemon.hpp"
#include "application/profile.hpp"

#include <algorithm>

namespace kasumi::application::daemon_detail {
namespace {

bool contains_case_insensitive(std::string_view haystack,
                               std::string_view needle) noexcept {
    if (needle.empty() || haystack.size() < needle.size()) {
        return false;
    }
    const auto it = std::ranges::search(haystack, needle, [](char a, char b) {
        const auto lower = [](char c) noexcept {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A'))
                                          : c;
        };
        return lower(a) == lower(b);
    });
    return !it.empty();
}

} // namespace

std::optional<std::string_view>
extract_rclone_remote_name(std::string_view remote_dir) noexcept {
    if (remote_dir.empty()) {
        return std::nullopt;
    }
    const auto colon = remote_dir.find(':');
    if (colon == std::string_view::npos || colon == 0U) {
        return std::nullopt;
    }
    const auto prefix = remote_dir.substr(0, colon);
    if (prefix.find('/') != std::string_view::npos ||
        prefix.find('\\') != std::string_view::npos) {
        return std::nullopt;
    }
    if (colon == 1U &&
        ((remote_dir[0] >= 'a' && remote_dir[0] <= 'z') ||
         (remote_dir[0] >= 'A' && remote_dir[0] <= 'Z')) &&
        (remote_dir.size() == 2U || remote_dir[2] == '\\' ||
         remote_dir[2] == '/')) {
        return std::nullopt;
    }
    return prefix;
}

bool is_concurrent_local_mutation_error(const Error& error) noexcept {
    return contains_case_insensitive(error.detail, "concurrent_modification") ||
           contains_case_insensitive(
               error.detail,
               "materialized tree does not match reconciled candidate tree") ||
           contains_case_insensitive(
               error.detail,
               "local materialization diverges from observed head");
}

bool is_transient_sync_error(const Error& error) noexcept {
    if (error.lock_busy || error.remote_busy) {
        return true;
    }
    if (error.empty_local_blocked || error.insufficient_disk_space) {
        return false;
    }
    if (error.code == ErrorCode::CredentialFailure ||
        error.code == ErrorCode::CredentialsRequired ||
        error.code == ErrorCode::InvalidProfile ||
        error.code == ErrorCode::ProfileNotFound) {
        return false;
    }
    if (is_concurrent_local_mutation_error(error)) {
        return true;
    }
    if (contains_case_insensitive(error.detail, "remote_busy") ||
        contains_case_insensitive(error.detail, "blocked by active") ||
        contains_case_insensitive(error.detail, "another execution") ||
        contains_case_insensitive(error.detail, "timeout") ||
        contains_case_insensitive(error.detail, "timed out") ||
        contains_case_insensitive(error.detail, "unreachable") ||
        contains_case_insensitive(error.detail, "connection") ||
        contains_case_insensitive(error.detail, "transport") ||
        contains_case_insensitive(error.detail, "backend") ||
        contains_case_insensitive(error.detail, "network") ||
        contains_case_insensitive(error.detail, "ratelimit") ||
        contains_case_insensitive(error.detail, "rate limit") ||
        contains_case_insensitive(error.detail, "rate_limit") ||
        contains_case_insensitive(error.detail, "too many requests") ||
        contains_case_insensitive(error.detail, "quota exceeded") ||
        contains_case_insensitive(error.detail, "throttl")) {
        return true;
    }
    if (contains_case_insensitive(error.detail, "composition_mismatch") ||
        contains_case_insensitive(error.detail, "initial sync") ||
        contains_case_insensitive(error.detail, "unauthenticated") ||
        contains_case_insensitive(error.detail, "corrupt") ||
        contains_case_insensitive(error.detail, "does not match") ||
        contains_case_insensitive(error.detail, "do not match") ||
        contains_case_insensitive(error.detail, "regression") ||
        contains_case_insensitive(error.detail,
                                  "requires absent local state")) {
        return false;
    }
    return error.code == ErrorCode::SynchronizationFailure ||
           error.code == ErrorCode::PlanFailure;
}

DaemonErrorCode map_profile_pause_error_code(ProfileErrorCode code) noexcept {
    switch (code) {
        case ProfileErrorCode::LockFailure:
            return DaemonErrorCode::LockBusy;
        case ProfileErrorCode::NotFound:
            return DaemonErrorCode::ProfileNotFound;
        default:
            return DaemonErrorCode::ConfigFailure;
    }
}

} // namespace kasumi::application::daemon_detail
