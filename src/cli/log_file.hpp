#ifndef KASUMI_CLI_LOG_FILE_HPP
#define KASUMI_CLI_LOG_FILE_HPP

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

namespace kasumi::cli {

std::expected<void, std::string>
validate_log_file_path(const std::filesystem::path& path);

std::string strip_ansi_sequences(std::string_view text);

std::expected<void, std::string>
append_log_line(const std::filesystem::path& path, std::string_view line);

std::expected<void, std::string>
append_text_log_entry(const std::filesystem::path& path,
                      std::string_view command,
                      int exit_code,
                      std::string_view summary);

} // namespace kasumi::cli

#endif
