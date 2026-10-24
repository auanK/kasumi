#ifndef KASUMI_PLATFORM_PRIVATE_STORAGE_HPP
#define KASUMI_PLATFORM_PRIVATE_STORAGE_HPP

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>

namespace kasumi::platform::private_storage {

inline constexpr std::intptr_t invalid_private_handle = -1;

enum class CleanupResult {
    Removed,
    AlreadyAbsent,
    IdentityMismatch,
    AccessDenied,
    FilesystemError
};

struct FileIdentity {
    std::uint64_t volume_or_dev{0};
    std::uint64_t file_id_low{0};
    std::uint64_t file_id_high{0};
    bool valid{false};

    constexpr bool operator==(const FileIdentity&) const = default;
};

void close_raw_handle(std::intptr_t handle) noexcept;

struct PrivateHandle {
    std::intptr_t value{invalid_private_handle};

    constexpr PrivateHandle() noexcept = default;
    constexpr PrivateHandle(std::intptr_t v) noexcept : value(v) {
    }
    ~PrivateHandle() noexcept {
        close();
    }
    PrivateHandle(const PrivateHandle&) = delete;
    PrivateHandle& operator=(const PrivateHandle&) = delete;
    PrivateHandle(PrivateHandle&& other) noexcept
        : value(std::exchange(other.value, invalid_private_handle)) {
    }
    PrivateHandle& operator=(PrivateHandle&& other) noexcept {
        if (this != &other) {
            close();
            value = std::exchange(other.value, invalid_private_handle);
        }
        return *this;
    }
    PrivateHandle& operator=(std::intptr_t v) noexcept {
        if (value != v) {
            close();
            value = v;
        }
        return *this;
    }

    void close() noexcept {
        if (value != invalid_private_handle) {
            close_raw_handle(value);
            value = invalid_private_handle;
        }
    }

    constexpr operator std::intptr_t() const noexcept {
        return value;
    }
    constexpr bool operator==(std::intptr_t v) const noexcept {
        return value == v;
    }
    constexpr bool operator!=(std::intptr_t v) const noexcept {
        return value != v;
    }
};

struct PrivateOutputFile {
    PrivateHandle handle{invalid_private_handle};
    std::filesystem::path path;
    FileIdentity identity{};
    bool published{false};

    bool is_open() const noexcept {
        return handle != invalid_private_handle;
    }
    bool is_published() const noexcept {
        return published;
    }
};

struct CreateFileError {
    std::string message;
    bool is_collision{false};

    const std::string& error() const noexcept {
        return message;
    }
};

std::expected<PrivateOutputFile, CreateFileError>
create_private_file(const std::filesystem::path& path);

std::expected<void, std::string>
publish_private_file(PrivateOutputFile& file,
                     const std::filesystem::path& target_path);

std::expected<void, std::string>
write_private_file(PrivateOutputFile& file, const void* data, std::size_t size);

std::expected<void, std::string>
flush_and_close_private_file(PrivateOutputFile& file);

void close_private_file(PrivateOutputFile& file) noexcept;

FileIdentity query_file_identity(const std::filesystem::path& path) noexcept;

CleanupResult remove_private_file_if_owned(PrivateOutputFile& file) noexcept;

std::expected<void, std::string>
create_directory(const std::filesystem::path& path);

std::expected<void, std::string>
ensure_directory(const std::filesystem::path& path);

std::expected<void, std::string>
protect_directory(const std::filesystem::path& path);

std::expected<void, std::string>
protect_tree(const std::filesystem::path& root);

std::expected<void, std::string> create_file(const std::filesystem::path& path);

std::expected<void, std::string>
protect_file(const std::filesystem::path& path);

std::expected<void, std::string>
write_atomically(const std::filesystem::path& path, std::string_view bytes);

} // namespace kasumi::platform::private_storage

#endif
