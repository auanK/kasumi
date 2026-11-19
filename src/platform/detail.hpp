#ifndef KASUMI_PLATFORM_DETAIL_HPP
#define KASUMI_PLATFORM_DETAIL_HPP

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <system_error>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace kasumi::platform::detail {

std::error_code rename_no_replace(const std::filesystem::path& source,
                                  const std::filesystem::path& destination);

#if defined(_WIN32)
template <typename Operation>
DWORD retry_windows_file_operation(Operation operation,
                                   bool retry_access_denied = true) {
    for (unsigned attempt = 0;; ++attempt) {
        const auto error = operation();
        const bool retryable =
            error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION ||
            (retry_access_denied && error == ERROR_ACCESS_DENIED);
        if (attempt == 3 || !retryable) {
            return error;
        }
        Sleep(10UL << attempt);
    }
}

DWORD rename_windows_handle(HANDLE file,
                            const std::filesystem::path& target,
                            FILE_INFO_BY_HANDLE_CLASS info_class,
                            DWORD flags);

using WalkEntryFn = std::expected<void, std::string> (*)(
    void* context, const std::filesystem::path& path, std::uint32_t attributes);

std::expected<void, std::string>
walk_windows_tree(const std::filesystem::path& root,
                  bool postorder_dirs,
                  WalkEntryFn on_entry,
                  void* context);
#endif

} // namespace kasumi::platform::detail

#endif
