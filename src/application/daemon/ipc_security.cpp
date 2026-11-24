#include "application/daemon/ipc_security.hpp"

#include "crypto/secure_memory.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <httplib.h>
#include <monocypher.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <system_error>
#include <vector>

namespace kasumi::application::daemon_detail {
namespace {

std::optional<std::uint8_t> hex_nibble(char ch) noexcept {
    if (ch >= '0' && ch <= '9') {
        return static_cast<std::uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<std::uint8_t>(10 + (ch - 'a'));
    }
    if (ch >= 'A' && ch <= 'F') {
        return static_cast<std::uint8_t>(10 + (ch - 'A'));
    }
    return std::nullopt;
}

std::string unlock_ad(std::string_view profile_name) {
    std::string ad{"kasumi-daemon-unlock-v1:"};
    ad.append(profile_name);
    return ad;
}

} // namespace

std::filesystem::path
daemon_lock_path(const std::filesystem::path& app_data_dir) {
    return app_data_dir / "daemon.lock";
}

std::filesystem::path
daemon_control_path(const std::filesystem::path& app_data_dir) {
    return app_data_dir / "daemon.control.json";
}

std::string encode_hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const std::uint8_t byte : bytes) {
        out.push_back(kHex[(byte >> 4U) & 0x0FU]);
        out.push_back(kHex[byte & 0x0FU]);
    }
    return out;
}

std::expected<std::vector<std::uint8_t>, std::string>
decode_hex(std::string_view hex, std::size_t expected_bytes) {
    if (hex.size() != expected_bytes * 2U) {
        return std::unexpected("unexpected hex payload length");
    }
    std::vector<std::uint8_t> out(expected_bytes, 0U);
    for (std::size_t i = 0; i < expected_bytes; ++i) {
        const auto hi = hex_nibble(hex[i * 2U]);
        const auto lo = hex_nibble(hex[i * 2U + 1U]);
        if (!hi || !lo) {
            crypto_wipe(out.data(), out.size());
            return std::unexpected("invalid hex digit");
        }
        out[i] = static_cast<std::uint8_t>((*hi << 4U) | *lo);
    }
    return out;
}

bool constant_time_verify_hex_token(
    std::string_view provided_hex,
    std::span<const std::uint8_t, kTokenSize> expected_token) noexcept {
    auto decoded = decode_hex(provided_hex, kTokenSize);
    if (!decoded) {
        return false;
    }
    const int diff = crypto_verify32(decoded->data(), expected_token.data());
    crypto_wipe(decoded->data(), decoded->size());
    return diff == 0;
}

void wipe_control_metadata(DaemonControlMetadata& metadata) noexcept {
    if (!metadata.auth_token_hex.empty()) {
        crypto::secure_memory::wipe(metadata.auth_token_hex.data(),
                                    metadata.auth_token_hex.size());
        metadata.auth_token_hex.clear();
    }
    if (!metadata.ipc_key_hex.empty()) {
        crypto::secure_memory::wipe(metadata.ipc_key_hex.data(),
                                    metadata.ipc_key_hex.size());
        metadata.ipc_key_hex.clear();
    }
}

bool validate_ipc_request_headers(
    const httplib::Request& req,
    std::uint16_t bound_port,
    std::span<const std::uint8_t, kTokenSize> expected_token) noexcept {
    if (req.has_header("Origin") || req.has_header("Referer") ||
        req.has_header("Sec-Fetch-Site") || req.has_header("Sec-Fetch-Mode")) {
        return false;
    }
    if (req.get_header_value_count("Host") != 1U) {
        return false;
    }
    {
        const auto host = req.get_header_value("Host");
        const std::string expected_plain = "127.0.0.1";
        const std::string expected_with_port =
            "127.0.0.1:" + std::to_string(bound_port);
        if (host != expected_plain && host != expected_with_port) {
            return false;
        }
    }
    if (req.get_header_value_count("X-Kasumi-Daemon-Token") != 1U) {
        return false;
    }
    const auto token = req.get_header_value("X-Kasumi-Daemon-Token");
    return constant_time_verify_hex_token(token, expected_token);
}

std::expected<void, std::string>
write_control_metadata(const std::filesystem::path& control_path,
                       const DaemonControlMetadata& metadata) {
    const auto parent = control_path.parent_path();
    if (auto dir_res = platform::private_storage::ensure_directory(parent);
        !dir_res) {
        return std::unexpected(dir_res.error());
    }
    nlohmann::json doc{
        {"version", 1},
        {"api_version", metadata.api_version},
        {"kasumi_version", metadata.kasumi_version},
        {"pid", metadata.pid},
        {"port", metadata.port},
        {"started_at", metadata.started_at_unix},
        {"auth_token", metadata.auth_token_hex},
        {"ipc_key", metadata.ipc_key_hex},
    };
    auto text = doc.dump();
    struct TextWiper {
        std::string& ref;
        ~TextWiper() noexcept {
            if (!ref.empty()) {
                crypto::secure_memory::wipe(ref.data(), ref.size());
            }
        }
    } text_wiper{text};
    if (auto wrote =
            platform::private_storage::write_atomically(control_path, text);
        !wrote) {
        return std::unexpected(wrote.error());
    }
    if (auto sec = platform::private_storage::protect_file(control_path);
        !sec) {
        return std::unexpected(sec.error());
    }
    return {};
}

std::expected<DaemonControlMetadata, std::string>
read_control_metadata(const std::filesystem::path& control_path) {
    std::string content;
    std::array<std::uint8_t, 4096> buf{};
    struct BufferWiper {
        std::string& s;
        std::array<std::uint8_t, 4096>& b;
        ~BufferWiper() noexcept {
            if (!s.empty()) {
                crypto::secure_memory::wipe(s.data(), s.size());
            }
            crypto::secure_memory::wipe(b.data(), b.size());
        }
    } buf_wiper{content, buf};
    const auto streamed = platform::private_storage::stream_regular_file(
        control_path, buf, [&](std::span<const std::uint8_t> chunk) {
            if (content.size() + chunk.size() > 16384U) {
                return false;
            }
            content.append(reinterpret_cast<const char*>(chunk.data()),
                           chunk.size());
            return true;
        });
    if (!streamed) {
        return std::unexpected("daemon control metadata unreadable: " +
                               streamed.error().detail);
    }
    try {
        const auto doc = nlohmann::json::parse(content);
        if (!doc.is_object() || doc.value("version", 0) != 1 ||
            !doc.contains("port") || !doc["port"].is_number_unsigned() ||
            !doc.contains("pid") || !doc["pid"].is_number_unsigned() ||
            !doc.contains("auth_token") || !doc["auth_token"].is_string() ||
            !doc.contains("ipc_key") || !doc["ipc_key"].is_string()) {
            return std::unexpected("invalid daemon control metadata format");
        }
        const auto port_u64 = doc["port"].get<std::uint64_t>();
        if (port_u64 == 0 || port_u64 > 65535U) {
            return std::unexpected("invalid daemon IPC port");
        }
        DaemonControlMetadata meta{
            .api_version = doc.value("api_version", std::uint32_t{1}),
            .kasumi_version = doc.value("kasumi_version", std::string{}),
            .pid = doc["pid"].get<std::uint64_t>(),
            .port = static_cast<std::uint16_t>(port_u64),
            .started_at_unix = doc.value("started_at", std::int64_t{0}),
            .auth_token_hex = doc["auth_token"].get<std::string>(),
            .ipc_key_hex = doc["ipc_key"].get<std::string>(),
        };
        auto auth_decoded = decode_hex(meta.auth_token_hex, kTokenSize);
        auto ipc_decoded = decode_hex(meta.ipc_key_hex, kTokenSize);
        const bool keys_ok =
            auth_decoded.has_value() && ipc_decoded.has_value();
        if (auth_decoded) {
            crypto::secure_memory::wipe(auth_decoded->data(),
                                        auth_decoded->size());
        }
        if (ipc_decoded) {
            crypto::secure_memory::wipe(ipc_decoded->data(),
                                        ipc_decoded->size());
        }
        if (!keys_ok) {
            wipe_control_metadata(meta);
            return std::unexpected("invalid daemon control keys");
        }
        return meta;
    } catch (const std::exception&) {
        return std::unexpected("corrupt daemon control JSON");
    }
}

void remove_control_metadata_best_effort(
    const std::filesystem::path& control_path) noexcept {
    std::error_code ec;
    std::filesystem::remove(control_path, ec);
}

std::expected<SealedUnlockPayload, std::string>
seal_key_payload(std::span<const std::uint8_t, kTokenSize> ipc_key,
                 std::span<const std::uint8_t, kTokenSize> master_key,
                 std::string_view profile_name) {
    std::array<std::uint8_t, 24> nonce{};
    if (auto rng = platform::random::fill_bytes(nonce); !rng) {
        return std::unexpected(rng.error());
    }
    std::array<std::uint8_t, 16> mac{};
    std::array<std::uint8_t, kTokenSize> cipher{};
    const auto ad = unlock_ad(profile_name);
    crypto_aead_lock(cipher.data(),
                     mac.data(),
                     ipc_key.data(),
                     nonce.data(),
                     reinterpret_cast<const std::uint8_t*>(ad.data()),
                     ad.size(),
                     master_key.data(),
                     master_key.size());
    return SealedUnlockPayload{
        .nonce_hex = encode_hex(nonce),
        .mac_hex = encode_hex(mac),
        .ciphertext_hex = encode_hex(cipher),
    };
}

std::expected<std::array<std::uint8_t, kTokenSize>, std::string>
open_key_payload(std::span<const std::uint8_t, kTokenSize> ipc_key,
                 const SealedUnlockPayload& payload,
                 std::string_view profile_name) {
    auto nonce = decode_hex(payload.nonce_hex, 24);
    auto mac = decode_hex(payload.mac_hex, 16);
    auto cipher = decode_hex(payload.ciphertext_hex, kTokenSize);
    if (!nonce || !mac || !cipher) {
        return std::unexpected("malformed encrypted unlock payload");
    }
    std::array<std::uint8_t, kTokenSize> clear{};
    const auto ad = unlock_ad(profile_name);
    const int auth =
        crypto_aead_unlock(clear.data(),
                           mac->data(),
                           ipc_key.data(),
                           nonce->data(),
                           reinterpret_cast<const std::uint8_t*>(ad.data()),
                           ad.size(),
                           cipher->data(),
                           cipher->size());
    crypto::secure_memory::wipe(nonce->data(), nonce->size());
    crypto::secure_memory::wipe(mac->data(), mac->size());
    crypto::secure_memory::wipe(cipher->data(), cipher->size());
    if (auth != 0) {
        crypto::secure_memory::wipe(clear.data(), clear.size());
        return std::unexpected("unlock payload authentication failed");
    }
    return clear;
}

} // namespace kasumi::application::daemon_detail
