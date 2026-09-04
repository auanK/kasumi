#ifndef KASUMI_TEST_TEMP_WORKSPACE_HPP
#define KASUMI_TEST_TEMP_WORKSPACE_HPP

#include <filesystem>
#include <memory>
#include <string_view>

namespace kasumi::test {

struct TempWorkspaceData {
    std::filesystem::path root;
};

using TempWorkspace =
    std::unique_ptr<TempWorkspaceData, void (*)(TempWorkspaceData*)>;

TempWorkspace make_temp_workspace(std::string_view label = "workspace");
void remove_temp_workspace(TempWorkspaceData* workspace) noexcept;

[[nodiscard]] const std::filesystem::path&
workspace_root(const TempWorkspace& workspace) noexcept;
[[nodiscard]] std::filesystem::path
workspace_path(const TempWorkspace& workspace,
               const std::filesystem::path& relative);

} // namespace kasumi::test

#endif
