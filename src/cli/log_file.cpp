#include "cli/log_file.hpp"

#include "platform/clock.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <format>
#include <fstream>
#include <system_error>

namespace kasumi::cli {

std::expected<void, std::string>
validate_log_file_path(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("log file path cannot be empty");
    }

    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (!error && status.type() != std::filesystem::file_type::not_found) {
        if (std::filesystem::is_symlink(status)) {
            return std::unexpected(std::format(
                "log file path '{}' cannot be a symbolic link",
                platform::path::to_utf8(path)));
        }
        if (std::filesystem::is_directory(status)) {
            return std::unexpected(std::format(
                "log file path '{}' is a directory",
                platform::path::to_utf8(path)));
        }
        if (!std::filesystem::is_regular_file(status)) {
            return std::unexpected(std::format(
                "log file path '{}' is not a regular file",
                platform::path::to_utf8(path)));
        }
    }

    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, error);
        if (error) {
            return std::unexpected(std::format(
                "cannot create log directory '{}': {}",
                platform::path::to_utf8(parent),
                error.message()));
        }
    }

    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out.is_open()) {
        return std::unexpected(std::format(
            "cannot open log file '{}' for appending",
            platform::path::to_utf8(path)));
    }
    return {};
}

std::string strip_ansi_sequences(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    std::size_t index = 0;
    while (index < text.size()) {
        const char ch = text[index];
        if (ch == '\x1b') {
            if (index + 1 < text.size() && text[index + 1] == '[') {
                index += 2;
                while (index < text.size()) {
                    const auto byte = static_cast<unsigned char>(text[index]);
                    ++index;
                    if (byte >= 0x40 && byte <= 0x7E) {
                        break;
                    }
                }
            } else if (index + 1 < text.size()) {
                index += 2;
            } else {
                ++index;
            }
            continue;
        }
        if (ch == '\r' || ch == '\n' || ch == '\t') {
            if (!out.empty() && out.back() != ' ') {
                out.push_back(' ');
            }
            ++index;
            continue;
        }
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20 || ch == '\x7f') {
            ++index;
            continue;
        }
        out.push_back(ch);
        ++index;
    }
    while (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return out;
}

std::string format_utc_iso8601_now() {
    const auto now = platform::clock::unix_seconds();
    if (!now) {
        return {};
    }
    const std::string utc = platform::clock::format_utc_timestamp(*now, true);
    if (utc.size() < 19 || utc[10] != ' ') {
        return {};
    }
    return std::format(
        "{}T{}Z",
        std::string_view{utc}.substr(0, 10),
        std::string_view{utc}.substr(11, 8));
}

std::expected<void, std::string>
append_log_line(const std::filesystem::path& path, std::string_view line) {
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out.is_open()) {
        return std::unexpected(std::format(
            "cannot open log file '{}' for appending",
            platform::path::to_utf8(path)));
    }
    out.write(line.data(), static_cast<std::streamsize>(line.size()));
    out.put('\n');
    out.flush();
    if (!out.good()) {
        return std::unexpected(std::format(
            "failed to write log entry to '{}'",
            platform::path::to_utf8(path)));
    }
    return {};
}

std::expected<void, std::string>
append_text_log_entry(const std::filesystem::path& path,
                      const TextLogEntry& entry) {
    const auto now = platform::clock::unix_seconds();
    const std::string timestamp =
        now ? platform::clock::format_local_timestamp(*now, true) : "-";
    const std::string clean_status = strip_ansi_sequences(entry.status);
    const std::string clean_command = strip_ansi_sequences(entry.command);
    const std::string clean_profile = strip_ansi_sequences(entry.profile);
    const std::string clean_summary = strip_ansi_sequences(entry.summary);

    const std::string_view final_status =
        clean_status.empty() ? std::string_view{"INFO"} : clean_status;
    const std::string_view final_command =
        clean_command.empty() ? std::string_view{"kasumi"} : clean_command;
    const std::string target = clean_profile.empty()
                                   ? std::string{final_command}
                                   : std::format("{} {}", final_command, clean_profile);

    std::string dur_suffix;
    if (entry.duration.has_value()) {
        const double secs =
            std::chrono::duration<double>(
                std::max(*entry.duration, std::chrono::nanoseconds::zero()))
                .count();
        dur_suffix = std::format(" ({:.3f} s)", secs);
    }

    std::string buffer =
        clean_summary.empty()
            ? std::format("[{}] [{}] {}{}\n",
                          timestamp,
                          final_status,
                          target,
                          dur_suffix)
            : std::format("[{}] [{}] {} | {}{}\n",
                          timestamp,
                          final_status,
                          target,
                          clean_summary,
                          dur_suffix);

    for (const auto& raw_detail : entry.detail_lines) {
        const std::string clean_detail = strip_ansi_sequences(raw_detail);
        if (!clean_detail.empty()) {
            buffer += "    ";
            buffer += clean_detail;
            buffer += '\n';
        }
    }

    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out.is_open()) {
        return std::unexpected(std::format(
            "cannot open log file '{}' for appending",
            platform::path::to_utf8(path)));
    }
    out.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    out.flush();
    if (!out.good()) {
        return std::unexpected(std::format(
            "failed to write log entry to '{}'",
            platform::path::to_utf8(path)));
    }
    return {};
}

} // namespace kasumi::cli
