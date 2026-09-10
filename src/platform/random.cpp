#include "platform/random.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <exception>
#include <limits>
#include <monocypher.h>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#elif defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
#include <stdlib.h>
#elif defined(__unix__) || defined(__unix) || defined(_POSIX_VERSION)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace kasumi::platform::random {

namespace {

[[maybe_unused]] std::string system_error_text(const char* operation) {
    return std::string{operation} + ": " + std::strerror(errno);
}

} // namespace

std::expected<void, std::string> fill_bytes(std::span<std::uint8_t> output) {
    if (output.empty()) {
        return {};
    }

#if defined(_WIN32)
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto remaining = output.size() - offset;
        const auto count = static_cast<ULONG>(std::min(
            remaining,
            static_cast<std::size_t>(std::numeric_limits<ULONG>::max())));
        const auto status = BCryptGenRandom(nullptr,
                                            output.data() + offset,
                                            count,
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status != 0) {
            return std::unexpected(
                "BCryptGenRandom falhou: " +
                std::to_string(static_cast<unsigned long>(status)));
        }
        offset += count;
    }
    return {};
#elif defined(__linux__)
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto count =
            ::getrandom(output.data() + offset, output.size() - offset, 0);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(system_error_text("getrandom falhou"));
        }
        if (count == 0) {
            return std::unexpected("getrandom retornou preenchimento vazio");
        }
        offset += static_cast<std::size_t>(count);
    }
    return {};
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
    arc4random_buf(output.data(), output.size());
    return {};
#elif defined(__unix__) || defined(__unix) || defined(_POSIX_VERSION)
    const int descriptor = ::open("/dev/urandom", O_RDONLY);
    if (descriptor < 0) {
        return std::unexpected(
            system_error_text("não foi possível abrir /dev/urandom"));
    }

    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto count =
            ::read(descriptor, output.data() + offset, output.size() - offset);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            const auto error = system_error_text("falha ao ler /dev/urandom");
            ::close(descriptor);
            return std::unexpected(error);
        }
        if (count == 0) {
            ::close(descriptor);
            return std::unexpected("/dev/urandom retornou preenchimento vazio");
        }
        offset += static_cast<std::size_t>(count);
    }

    if (::close(descriptor) != 0) {
        return std::unexpected(
            system_error_text("falha ao fechar /dev/urandom"));
    }
    return {};
#else
    return std::unexpected(
        "fonte CSPRNG do sistema não suportada nesta plataforma");
#endif
}

std::expected<std::string, std::string> hex_id(std::size_t byte_count) {
    if (byte_count == 0) {
        return std::unexpected(
            "o tamanho do identificador aleatório não pode ser zero");
    }
    if (byte_count > (std::numeric_limits<std::size_t>::max)() / 2) {
        return std::unexpected(
            "o tamanho do identificador aleatório é grande demais");
    }

    std::vector<std::uint8_t> bytes;
    try {
        bytes.resize(byte_count);
        auto result = fill_bytes(bytes);
        if (!result) {
            crypto_wipe(bytes.data(), bytes.size());
            return std::unexpected(result.error());
        }

        constexpr char digits[] = "0123456789abcdef";
        std::string id(byte_count * 2, '\0');
        for (std::size_t index = 0; index < bytes.size(); ++index) {
            id[index * 2] = digits[bytes[index] >> 4];
            id[index * 2 + 1] = digits[bytes[index] & 0x0fU];
        }
        crypto_wipe(bytes.data(), bytes.size());
        return id;
    } catch (const std::exception& exception) {
        if (!bytes.empty()) {
            crypto_wipe(bytes.data(), bytes.size());
        }
        return std::unexpected(
            std::string{"não foi possível gerar identificador aleatório: "} +
            exception.what());
    }
}

} // namespace kasumi::platform::random
