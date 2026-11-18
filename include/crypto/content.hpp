#ifndef KASUMI_CRYPTO_CONTENT_HPP
#define KASUMI_CRYPTO_CONTENT_HPP

#include "core/hasher.hpp"

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace kasumi::crypto::content {

// Computes the BLAKE3 hash of the bytes accessible at the path.
std::expected<Hash, std::string>
hash_file(const std::filesystem::path& path,
          std::atomic<std::uint64_t>* bytes_read = nullptr);

// Verifies hash and optional size; rejects the path if it is a symbolic link.
std::expected<void, std::string>
verify_file(const std::filesystem::path& path,
            std::string_view expected_hash,
            std::optional<std::uint64_t> expected_size = std::nullopt);

} // namespace kasumi::crypto::content

#endif
