#include "cli/log_file.hpp"

#include "platform/clock.hpp"
#include "platform/path.hpp"

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
                      std::string_view command,
                      int exit_code,
                      std::string_view summary) {
    const auto now = platform::clock::unix_seconds();
    const std::string timestamp =
        now ? platform::clock::format_utc_timestamp(*now, true) : "-";
    const std::string clean_command = strip_ansi_sequences(command);
    const std::string clean_summary = strip_ansi_sequences(summary);
    const std::string line =
        clean_summary.empty()
            ? std::format("[{}] command={} exit={}",
                          timestamp,
                          clean_command.empty() ? "kasumi" : clean_command,
                          exit_code)
            : std::format("[{}] command={} exit={} {}",
                          timestamp,
                          clean_command.empty() ? "kasumi" : clean_command,
                          exit_code,
                          clean_summary);
    return append_log_line(path, line);
}

} // namespace kasumi::cli
