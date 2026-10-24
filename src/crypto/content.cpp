#include "crypto/content.hpp"

#include "crypto/secure_memory.hpp"

#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <blake3.h>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <system_error>

namespace kasumi::crypto::content {

namespace {

struct BufferWipeGuard {
    char* data = nullptr;
    std::size_t size = 0;

    ~BufferWipeGuard() noexcept {
        if (data != nullptr && size > 0) {
            secure_memory::wipe(data, size);
            platform::perf_trace::count("content hash wipe bytes", size);
        }
    }
};

} // namespace

std::expected<Hash, std::string> hash_file(const std::filesystem::path& path) {
    try {
        const auto open_trace = platform::perf_trace::begin();
        std::ifstream input(path, std::ios::binary);
        platform::perf_trace::finish("content hash input open", open_trace);
        if (!input) {
            return std::unexpected("could not open file for hashing: " +
                                   platform::path::to_utf8(path));
        }

        blake3_hasher state;
        blake3_hasher_init(&state);
        const auto buffer_trace = platform::perf_trace::begin();
        constexpr std::size_t buffer_size = 64U * 1024U;
        auto buffer = std::make_unique_for_overwrite<char[]>(buffer_size);
        platform::perf_trace::finish("content hash buffer setup", buffer_trace);
        platform::perf_trace::count("content hash scratch bytes", buffer_size);
        BufferWipeGuard wipe_guard{buffer.get(), buffer_size};
        std::uint64_t read_calls = 0;
        std::uint64_t read_bytes = 0;

        while (input) {
            const auto read_trace = platform::perf_trace::begin();
            input.read(buffer.get(), static_cast<std::streamsize>(buffer_size));
            platform::perf_trace::finish("content hash read", read_trace);
            ++read_calls;
            const auto count = input.gcount();
            if (count > 0) {
                const auto hash_trace = platform::perf_trace::begin();
                blake3_hasher_update(
                    &state, buffer.get(), static_cast<std::size_t>(count));
                platform::perf_trace::finish("content hash BLAKE3", hash_trace);
                read_bytes += static_cast<std::uint64_t>(count);
            }
        }
        platform::perf_trace::count("content hash read calls", read_calls);
        platform::perf_trace::count("content hash read bytes", read_bytes);

        if (input.bad() || (input.fail() && !input.eof())) {
            return std::unexpected("failed to read file for hashing: " +
                                   platform::path::to_utf8(path));
        }

        Hash result{};
        const auto finalize_trace = platform::perf_trace::begin();
        blake3_hasher_finalize(&state,
                               reinterpret_cast<std::uint8_t*>(result.data()),
                               result.size());
        platform::perf_trace::finish("content hash finalize", finalize_trace);
        return result;
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not compute file hash: "} +
                               exception.what());
    }
}

std::expected<void, std::string>
verify_file(const std::filesystem::path& path,
            std::string_view expected_hash,
            std::optional<std::uint64_t> expected_size) {
    auto decoded_hash = hash_from_hex(expected_hash);
    if (!decoded_hash) {
        return std::unexpected("invalid expected hash: " +
                               decoded_hash.error());
    }

    try {
        std::error_code error;
        const auto file_status = std::filesystem::symlink_status(path, error);
        if (error) {
            return std::unexpected("could not query file: " + error.message());
        }
        if (std::filesystem::is_symlink(file_status)) {
            return std::unexpected("path is a symlink and cannot be verified");
        }
        if (file_status.type() == std::filesystem::file_type::not_found) {
            return std::unexpected("file does not exist");
        }
        if (!std::filesystem::is_regular_file(file_status)) {
            return std::unexpected("path is not a regular file");
        }

        if (expected_size) {
            const auto actual_size = std::filesystem::file_size(path, error);
            if (error) {
                return std::unexpected("could not read file size: " +
                                       error.message());
            }
            if (actual_size != *expected_size) {
                return std::unexpected(
                    "file size does not match expected size");
            }
        }

        auto actual_hash = hash_file(path);
        if (!actual_hash) {
            return std::unexpected(actual_hash.error());
        }
        if (*actual_hash != *decoded_hash) {
            return std::unexpected("file content does not match expected hash");
        }
        return {};
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not verify file: "} +
                               exception.what());
    }
}

} // namespace kasumi::crypto::content
