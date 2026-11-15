#ifndef KASUMI_PLATFORM_DETAIL_HPP
#define KASUMI_PLATFORM_DETAIL_HPP

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <system_error>

namespace kasumi::platform::detail {

std::error_code rename_no_replace(const std::filesystem::path& source,
                                  const std::filesystem::path& destination);

#if defined(_WIN32)
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
