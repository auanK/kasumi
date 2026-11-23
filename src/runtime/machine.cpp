#include "runtime/machine.hpp"

#include "platform/machine.hpp"
#include "platform/private_storage.hpp"
#include "platform/profile_lock.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <optional>
#include <system_error>
#include <thread>

namespace kasumi::runtime {
namespace {

bool is_zero_id(const std::array<std::uint8_t, MACHINE_ID_BYTES>& id) noexcept {
    return std::ranges::all_of(id, [](std::uint8_t byte) {
        return byte == 0;
    });
}

std::optional<std::uint8_t> hex_nibble(char ch) noexcept {
    if (ch >= '0' && ch <= '9') {
        return static_cast<std::uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<std::uint8_t>(ch - 'a' + 10);
    }
    return std::nullopt;
}

std::string
encode_hex(const std::array<std::uint8_t, MACHINE_ID_BYTES>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(MACHINE_ID_HEX_LENGTH);
    for (const auto byte : bytes) {
        output.push_back(digits[(byte >> 4U) & 0x0FU]);
        output.push_back(digits[byte & 0x0FU]);
    }
    return output;
}

std::expected<
    std::optional<
        std::pair<std::array<std::uint8_t, MACHINE_ID_BYTES>, std::string>>,
    Error>
read_machine_id_file(const std::filesystem::path& id_path) {
    if (platform::private_storage::is_reparse_or_symlink(id_path)) {
        return fail(ErrorCode::PathEscape,
                    "machine identity file must not be a symlink");
    }

    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(id_path, status_error);
    if (status_error == std::errc::no_such_file_or_directory ||
        (!status_error &&
         status.type() == std::filesystem::file_type::not_found)) {
        return std::nullopt;
    }
    if (status_error) {
        return fail(ErrorCode::IoFailure,
                    "could not inspect machine identity file: " +
                        status_error.message());
    }
    if (std::filesystem::is_symlink(status)) {
        return fail(ErrorCode::PathEscape,
                    "machine identity file must not be a symlink");
    }
    if (!std::filesystem::is_regular_file(status)) {
        return fail(ErrorCode::IoFailure,
                    "machine identity path is not a regular file");
    }

    std::array<std::uint8_t, 64> scratch{};
    std::string raw;
    bool oversized = false;
    const auto streamed = platform::private_storage::stream_regular_file(
        id_path, scratch, [&](std::span<const std::uint8_t> chunk) {
            if (raw.size() + chunk.size() > scratch.size()) {
                oversized = true;
                return false;
            }
            raw.append(reinterpret_cast<const char*>(chunk.data()),
                       chunk.size());
            return true;
        });
    if (oversized) {
        return fail(ErrorCode::IoFailure, "machine identity file is invalid");
    }
    if (!streamed) {
        using Kind = platform::private_storage::StreamErrorKind;
        if (streamed.error().kind == Kind::NotFound) {
            return std::nullopt;
        }
        if (streamed.error().kind == Kind::Symlink) {
            return fail(ErrorCode::PathEscape,
                        "machine identity file must not be a symlink");
        }
        return fail(ErrorCode::IoFailure, streamed.error().detail);
    }

    while (!raw.empty() &&
           (raw.back() == '\n' || raw.back() == '\r' || raw.back() == ' ')) {
        raw.pop_back();
    }
    if (raw.size() != MACHINE_ID_HEX_LENGTH) {
        return fail(ErrorCode::IoFailure, "machine identity file is corrupt");
    }

    std::array<std::uint8_t, MACHINE_ID_BYTES> parsed{};
    for (std::size_t i = 0; i < MACHINE_ID_BYTES; ++i) {
        const auto hi = hex_nibble(raw[i * 2]);
        const auto lo = hex_nibble(raw[i * 2 + 1]);
        if (!hi || !lo) {
            return fail(ErrorCode::IoFailure,
                        "machine identity file contains invalid hex");
        }
        parsed[i] = static_cast<std::uint8_t>((*hi << 4U) | *lo);
    }
    if (is_zero_id(parsed)) {
        return fail(ErrorCode::IoFailure, "machine identity cannot be zero");
    }
    return std::make_pair(parsed, std::move(raw));
}

struct ScopedLockGuard {
    std::intptr_t handle = platform::invalid_profile_lock;
    ~ScopedLockGuard() noexcept {
        platform::release_profile_lock(handle);
    }
};

} // namespace

std::expected<MachineIdentity, Error>
resolve_machine_identity(const std::filesystem::path& app_data_dir,
                         bool allow_create) {
    if (app_data_dir.empty()) {
        return fail(ErrorCode::IoFailure,
                    "application data directory is empty");
    }

    const std::string machine_name = platform::machine::host_name();
    if (platform::private_storage::is_reparse_or_symlink(app_data_dir)) {
        return fail(ErrorCode::PathEscape,
                    "application data directory must not be a symlink");
    }

    std::error_code dir_error;
    const auto dir_status =
        std::filesystem::symlink_status(app_data_dir, dir_error);
    const bool dir_missing =
        dir_error == std::errc::no_such_file_or_directory ||
        (!dir_error &&
         dir_status.type() == std::filesystem::file_type::not_found);
    if (dir_error && !dir_missing) {
        return fail(ErrorCode::IoFailure,
                    "could not inspect application data directory: " +
                        dir_error.message());
    }
    if (!dir_missing) {
        if (std::filesystem::is_symlink(dir_status)) {
            return fail(ErrorCode::PathEscape,
                        "application data directory must not be a symlink");
        }
        if (!std::filesystem::is_directory(dir_status)) {
            return fail(ErrorCode::IoFailure,
                        "application data path is not a directory");
        }
    } else if (!allow_create) {
        return MachineIdentity{
            .id = {},
            .id_hex = {},
            .name = machine_name,
        };
    }

    const auto id_path = app_data_dir / "machine.id";
    if (!dir_missing) {
        auto existing = read_machine_id_file(id_path);
        if (!existing) {
            return std::unexpected(existing.error());
        }
        if (existing->has_value()) {
            return MachineIdentity{
                .id = (*existing)->first,
                .id_hex = std::move((*existing)->second),
                .name = machine_name,
            };
        }
    }

    if (!allow_create) {
        return MachineIdentity{
            .id = {},
            .id_hex = {},
            .name = machine_name,
        };
    }

    if (dir_missing) {
        auto created_dir =
            platform::private_storage::create_directory(app_data_dir);
        if (!created_dir) {
            return fail(ErrorCode::IoFailure, created_dir.error());
        }
    }

    const auto lock_path = app_data_dir / "machine.id.lock";
    ScopedLockGuard lock_guard{};
    std::string lock_error;
    for (int attempt = 0; attempt < 50; ++attempt) {
        auto locked = platform::acquire_profile_lock(lock_path);
        if (locked) {
            lock_guard.handle = *locked;
            break;
        }
        lock_error = locked.error();
        auto existing = read_machine_id_file(id_path);
        if (!existing) {
            return std::unexpected(existing.error());
        }
        if (existing->has_value()) {
            return MachineIdentity{
                .id = (*existing)->first,
                .id_hex = std::move((*existing)->second),
                .name = machine_name,
            };
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (lock_guard.handle == platform::invalid_profile_lock) {
        return fail(ErrorCode::IoFailure,
                    lock_error.empty() ? "could not lock machine identity file"
                                       : lock_error);
    }

    auto existing = read_machine_id_file(id_path);
    if (!existing) {
        return std::unexpected(existing.error());
    }
    if (existing->has_value()) {
        return MachineIdentity{
            .id = (*existing)->first,
            .id_hex = std::move((*existing)->second),
            .name = machine_name,
        };
    }

    std::array<std::uint8_t, MACHINE_ID_BYTES> generated{};
    for (int attempt = 0; attempt < 8; ++attempt) {
        auto filled = platform::random::fill_bytes(generated);
        if (!filled) {
            return fail(ErrorCode::IoFailure, filled.error());
        }
        if (!is_zero_id(generated)) {
            break;
        }
    }
    if (is_zero_id(generated)) {
        return fail(ErrorCode::IoFailure,
                    "failed to generate non-zero machine identity");
    }

    auto hex = encode_hex(generated);
    auto written =
        platform::private_storage::write_atomically(id_path, hex + "\n");
    if (!written) {
        return fail(ErrorCode::IoFailure, written.error());
    }

    return MachineIdentity{
        .id = generated,
        .id_hex = std::move(hex),
        .name = machine_name,
    };
}

} // namespace kasumi::runtime
