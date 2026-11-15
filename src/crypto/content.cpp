#include "crypto/content.hpp"

#include "crypto/secure_memory.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <blake3.h>
#include <cstdint>
#include <fstream>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

namespace kasumi::crypto::content {

std::expected<Hash, std::string> hash_file(const std::filesystem::path& path) {
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return std::unexpected("could not open file for hashing: " +
                                   platform::path::to_utf8(path));
        }

        blake3_hasher state;
        blake3_hasher_init(&state);
        secure_memory::WipeGuard state_guard{state};
        constexpr std::size_t buffer_size = 64U * 1024U;
        std::vector<std::uint8_t> buffer(buffer_size);
        secure_memory::WipeGuard wipe_guard{buffer};

        while (input) {
            input.read(reinterpret_cast<char*>(buffer.data()),
                       static_cast<std::streamsize>(buffer_size));
            if (const auto count = input.gcount(); count > 0) {
                blake3_hasher_update(
                    &state, buffer.data(), static_cast<std::size_t>(count));
            }
        }

        if (input.bad() || (input.fail() && !input.eof())) {
            return std::unexpected("failed to read file for hashing: " +
                                   platform::path::to_utf8(path));
        }

        Hash result{};
        blake3_hasher_finalize(&state,
                               reinterpret_cast<std::uint8_t*>(result.data()),
                               result.size());
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
        constexpr std::size_t buffer_size = 64U * 1024U;
        std::vector<std::uint8_t> buffer(buffer_size);
        secure_memory::WipeGuard wipe_guard{buffer};
        blake3_hasher state;
        blake3_hasher_init(&state);
        secure_memory::WipeGuard state_guard{state};

        auto streamed = platform::private_storage::stream_regular_file(
            path,
            buffer,
            [&](std::span<const std::uint8_t> chunk) {
                blake3_hasher_update(&state, chunk.data(), chunk.size());
            },
            expected_size);
        if (!streamed) {
            using Kind = platform::private_storage::StreamErrorKind;
            const auto& err = streamed.error();
            switch (err.kind) {
                case Kind::NotFound:
                    return std::unexpected("file does not exist");
                case Kind::Symlink:
                    return std::unexpected(
                        "path is a symlink and cannot be verified");
                case Kind::NotRegular:
                    return std::unexpected("path is not a regular file");
                case Kind::SizeMismatch:
                    return std::unexpected(
                        "file size does not match expected size");
                case Kind::ReadFailed:
                    return std::unexpected("failed to read file for hashing: " +
                                           platform::path::to_utf8(path));
                case Kind::OpenFailed:
                case Kind::Aborted:
                    return std::unexpected("could not query file: " +
                                           err.detail);
            }
        }

        Hash actual_hash{};
        blake3_hasher_finalize(
            &state,
            reinterpret_cast<std::uint8_t*>(actual_hash.data()),
            actual_hash.size());
        if (actual_hash != *decoded_hash) {
            return std::unexpected("file content does not match expected hash");
        }
        return {};
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not verify file: "} +
                               exception.what());
    }
}

} // namespace kasumi::crypto::content
