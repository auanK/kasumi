#ifndef KASUMI_CLI_LOG_FILE_HPP
#define KASUMI_CLI_LOG_FILE_HPP

#include <chrono>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::cli {

struct TextLogEntry {
    std::string_view status;
    std::string_view command;
    std::string_view profile;
    std::string_view summary;
    std::optional<std::chrono::nanoseconds> duration = std::nullopt;
    std::vector<std::string> detail_lines = {};
};

std::expected<void, std::string>
validate_log_file_path(const std::filesystem::path& path);

std::string strip_ansi_sequences(std::string_view text);

std::string format_utc_iso8601_now();

std::expected<void, std::string>
append_log_line(const std::filesystem::path& path, std::string_view line);

std::expected<void, std::string>
append_text_log_entry(const std::filesystem::path& path,
                      const TextLogEntry& entry);

} // namespace kasumi::cli

#endif
