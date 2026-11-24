#include "application/profile.hpp"
#include "core/ignore.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "runtime/profile.hpp"

#include <algorithm>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace kasumi::application {
namespace {

std::unexpected<ProfileError> fail_ignore(ProfileErrorCode code,
                                          std::string detail) {
    return std::unexpected(
        ProfileError{.code = code, .detail = std::move(detail)});
}

std::expected<runtime::ProfileData, ProfileError>
load_target_profile(const ExecutionEnvironment& environment,
                    std::string_view profile_name) {
    if (!runtime::is_valid_profile_name(profile_name)) {
        return fail_ignore(ProfileErrorCode::InvalidName,
                           "invalid profile name");
    }
    auto loaded = runtime::load_profile(
        environment.app_data_dir / "config.toml", profile_name);
    if (!loaded) {
        const auto code =
            loaded.error().code == runtime::ErrorCode::ConfigNotFound ||
                    loaded.error().code == runtime::ErrorCode::ProfileNotFound
                ? ProfileErrorCode::NotFound
                : ProfileErrorCode::ConfigFailure;
        return fail_ignore(code, loaded.error().detail);
    }
    return *loaded;
}

bool is_plain_directory(const std::filesystem::path& path,
                        std::string& error_detail) {
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(path, ec);
    if (ec) {
        error_detail = ec == std::errc::no_such_file_or_directory
                           ? "synchronized local directory does not exist"
                           : ec.message();
        return false;
    }
    if (std::filesystem::is_symlink(st) ||
        platform::private_storage::is_reparse_or_symlink(path) ||
        !std::filesystem::is_directory(st)) {
        error_detail = "synchronized local directory must be a plain directory";
        return false;
    }
    return true;
}

struct NormalizedCheckTarget {
    std::string logical_path;
    bool is_directory = false;
};

std::expected<NormalizedCheckTarget, ProfileError>
normalize_check_path(const std::filesystem::path& local_dir,
                     std::string_view raw_input) {
    if (raw_input.empty()) {
        return fail_ignore(ProfileErrorCode::ConfigFailure,
                           "path to check cannot be empty");
    }
    std::string text{raw_input};
    bool trailing_dir = text.ends_with('/') || text.ends_with('\\');
    while (text.size() > 1 && (text.ends_with('/') || text.ends_with('\\'))) {
        text.pop_back();
    }

    const auto input_path = platform::path::from_utf8(text);
    std::filesystem::path rel;
    if (input_path.is_absolute()) {
        std::error_code ec;
        const auto lex_local = local_dir.lexically_normal();
        const auto lex_input = input_path.lexically_normal();
        rel = lex_input.lexically_relative(lex_local);
        if (ec || rel.empty()) {
            return fail_ignore(
                ProfileErrorCode::ConfigFailure,
                "absolute path must reside inside the profile local_dir");
        }
    } else {
        rel = input_path.lexically_normal();
    }

    auto logical = platform::path::to_logical_utf8(rel);
    while (logical.starts_with("./")) {
        logical.erase(0, 2);
    }
    if (logical.empty() || logical == "." || logical == ".." ||
        logical.starts_with("../") ||
        logical.find("/../") != std::string::npos || logical.ends_with("/..") ||
        logical.front() == '/') {
        return fail_ignore(ProfileErrorCode::ConfigFailure,
                           "path escapes or names the synchronized root");
    }

    bool is_dir = trailing_dir;
    if (!is_dir) {
        std::error_code ec;
        const auto candidate = local_dir / rel;
        const auto st = std::filesystem::symlink_status(candidate, ec);
        if (!ec && !std::filesystem::is_symlink(st) &&
            std::filesystem::is_directory(st)) {
            is_dir = true;
        }
    }
    return NormalizedCheckTarget{
        .logical_path = std::move(logical),
        .is_directory = is_dir,
    };
}

IgnoreDispositionKind to_app_disposition(ignore::IgnoreDisposition d) noexcept {
    switch (d) {
        case ignore::IgnoreDisposition::Managed:
            return IgnoreDispositionKind::Managed;
        case ignore::IgnoreDisposition::IgnoredProtected:
            return IgnoreDispositionKind::IgnoredProtected;
        case ignore::IgnoreDisposition::IgnoredDisposable:
            return IgnoreDispositionKind::IgnoredDisposable;
    }
    return IgnoreDispositionKind::Managed;
}

std::string preset_content(IgnorePreset preset) {
    constexpr std::string_view kMinimal = "# OS metadata (disposable)\n"
                                          "(?d).DS_Store\n"
                                          "(?d)Thumbs.db\n"
                                          "(?d)desktop.ini\n";
    constexpr std::string_view kOffice =
        "# Office & editor lock/temp files (disposable)\n"
        "(?d)~$*\n"
        "(?d).~lock.*\n"
        "(?d)*.tmp\n";
    constexpr std::string_view kDev = "# Version control & build artifacts\n"
                                      ".git/\n"
                                      "node_modules/\n"
                                      "build/\n"
                                      "dist/\n"
                                      "target/\n"
                                      ".venv/\n"
                                      "__pycache__/\n"
                                      "(?d)*.pyc\n";

    switch (preset) {
        case IgnorePreset::Minimal:
            return std::string{kMinimal};
        case IgnorePreset::Office:
            return std::format("{}\n{}", kMinimal, kOffice);
        case IgnorePreset::Dev:
            return std::format("{}\n{}", kMinimal, kDev);
        case IgnorePreset::Default:
            return std::format("{}\n{}\n{}", kMinimal, kOffice, kDev);
    }
    return std::string{kMinimal};
}

} // namespace

std::string_view to_string(IgnorePreset preset) noexcept {
    switch (preset) {
        case IgnorePreset::Default:
            return "default";
        case IgnorePreset::Dev:
            return "dev";
        case IgnorePreset::Office:
            return "office";
        case IgnorePreset::Minimal:
            return "minimal";
    }
    return "default";
}

std::expected<IgnoreCheckReport, ProfileError>
check_profile_ignore(const ExecutionEnvironment& environment,
                     std::string_view profile_name,
                     std::span<const std::string> paths) {
    if (paths.empty()) {
        return fail_ignore(ProfileErrorCode::ConfigFailure,
                           "at least one path is required");
    }
    auto prof = load_target_profile(environment, profile_name);
    if (!prof) {
        return std::unexpected(prof.error());
    }
    std::string dir_err;
    if (!is_plain_directory(prof->local_dir, dir_err)) {
        return fail_ignore(ProfileErrorCode::StorageFailure,
                           std::move(dir_err));
    }

    const auto ignore_path = prof->local_dir / ".kasumiignore";
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(ignore_path, ec);
    const bool present =
        !ec && st.type() != std::filesystem::file_type::not_found;
    if (ec && ec != std::errc::no_such_file_or_directory) {
        return fail_ignore(ProfileErrorCode::StorageFailure, ec.message());
    }

    const auto rules = ignore::load_ignore_list(ignore_path);
    if (rules.parse_error) {
        return fail_ignore(ProfileErrorCode::ConfigFailure,
                           std::format(".kasumiignore line {}: {}",
                                       rules.parse_error->line,
                                       rules.parse_error->detail));
    }

    IgnoreCheckReport report{
        .profile_name = prof->name,
        .ignore_file = ignore_path,
        .ignore_file_present = present,
    };
    report.items.reserve(paths.size());
    for (const auto& raw_path : paths) {
        auto normalized = normalize_check_path(prof->local_dir, raw_path);
        if (!normalized) {
            return std::unexpected(normalized.error());
        }
        const auto match = ignore::inspect_ignore(
            normalized->logical_path, normalized->is_directory, rules);
        report.items.push_back(IgnoreCheckItem{
            .input_path = raw_path,
            .logical_path = std::move(normalized->logical_path),
            .is_directory = normalized->is_directory,
            .disposition = to_app_disposition(match.disposition),
            .reserved_internal = match.reserved_internal,
            .matched_rule = match.matched,
            .rule_line = match.line,
            .rule_text = match.raw,
        });
    }
    return report;
}

std::expected<IgnoreInitReport, ProfileError>
init_profile_ignore(const ExecutionEnvironment& environment,
                    std::string_view profile_name,
                    IgnorePreset preset,
                    bool force,
                    bool dry_run) {
    auto prof = load_target_profile(environment, profile_name);
    if (!prof) {
        return std::unexpected(prof.error());
    }
    std::string dir_err;
    if (!is_plain_directory(prof->local_dir, dir_err)) {
        return fail_ignore(ProfileErrorCode::StorageFailure,
                           std::move(dir_err));
    }

    const auto ignore_path = prof->local_dir / ".kasumiignore";
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(ignore_path, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
        return fail_ignore(ProfileErrorCode::StorageFailure, ec.message());
    }
    const bool exists = st.type() != std::filesystem::file_type::not_found;
    if (exists &&
        (std::filesystem::is_symlink(st) ||
         platform::private_storage::is_reparse_or_symlink(ignore_path) ||
         !std::filesystem::is_regular_file(st))) {
        return fail_ignore(ProfileErrorCode::StorageFailure,
                           ".kasumiignore must be a regular non-symlink file");
    }
    if (exists && !force) {
        return fail_ignore(
            ProfileErrorCode::AlreadyExists,
            ".kasumiignore already exists; pass --force to overwrite");
    }

    auto content = preset_content(preset);
    if (!dry_run) {
        if (auto saved = platform::private_storage::write_atomically(
                ignore_path, content);
            !saved) {
            return fail_ignore(ProfileErrorCode::StorageFailure, saved.error());
        }
        static_cast<void>(
            platform::durability::sync_parent_directory(ignore_path));
    }

    return IgnoreInitReport{
        .profile_name = prof->name,
        .ignore_file = ignore_path,
        .preset = preset,
        .created = !dry_run && !exists,
        .overwritten = !dry_run && exists,
        .dry_run = dry_run,
        .content = std::move(content),
    };
}

} // namespace kasumi::application
