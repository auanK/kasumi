#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "runtime/machine.hpp"

#include <algorithm>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>

namespace {

TEST(RuntimeMachineIdentityTest,
     ReadOnlyResolutionDoesNotCreateAppDataOrMachineId) {
    auto workspace = kasumi::test::make_temp_workspace("runtime-machine-ro");
    const auto app = kasumi::test::workspace_path(workspace, "app");

    const auto identity = kasumi::runtime::resolve_machine_identity(app, false);
    ASSERT_TRUE(identity.has_value()) << identity.error().detail;
    EXPECT_TRUE(identity->id_hex.empty());
    EXPECT_TRUE(std::ranges::all_of(
        identity->id, [](std::uint8_t byte) { return byte == 0; }));
    EXPECT_FALSE(identity->name.empty());
    EXPECT_FALSE(std::filesystem::exists(app));

    // Existing app dir without machine.id also remains untouched in read-only.
    std::filesystem::create_directories(app);
    const auto before = kasumi::test::snapshot_tree(app);
    const auto second = kasumi::runtime::resolve_machine_identity(app, false);
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_TRUE(second->id_hex.empty());
    EXPECT_EQ(kasumi::test::snapshot_tree(app), before);
}

TEST(RuntimeMachineIdentityTest, CreatesPersistsAndLoadsIdenticalMachineId) {
    auto workspace = kasumi::test::make_temp_workspace("runtime-machine-rw");
    const auto app = kasumi::test::workspace_path(workspace, "app");

    const auto created = kasumi::runtime::resolve_machine_identity(app, true);
    ASSERT_TRUE(created.has_value()) << created.error().detail;
    EXPECT_EQ(created->id_hex.size(), kasumi::runtime::MACHINE_ID_HEX_LENGTH);
    EXPECT_TRUE(std::ranges::any_of(
        created->id, [](std::uint8_t byte) { return byte != 0; }));
    EXPECT_TRUE(std::filesystem::is_regular_file(app / "machine.id"));

    const auto loaded_rw =
        kasumi::runtime::resolve_machine_identity(app, true);
    ASSERT_TRUE(loaded_rw.has_value()) << loaded_rw.error().detail;
    EXPECT_EQ(loaded_rw->id, created->id);
    EXPECT_EQ(loaded_rw->id_hex, created->id_hex);

    const auto loaded_ro =
        kasumi::runtime::resolve_machine_identity(app, false);
    ASSERT_TRUE(loaded_ro.has_value()) << loaded_ro.error().detail;
    EXPECT_EQ(loaded_ro->id, created->id);
    EXPECT_EQ(loaded_ro->id_hex, created->id_hex);
}

TEST(RuntimeMachineIdentityTest, RejectsMalformedZeroAndSymlinkMachineId) {
    auto workspace =
        kasumi::test::make_temp_workspace("runtime-machine-invalid");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    std::filesystem::create_directories(app);

    kasumi::test::write_text(app / "machine.id", "not-valid-hex\n");
    EXPECT_FALSE(kasumi::runtime::resolve_machine_identity(app, false));
    EXPECT_FALSE(kasumi::runtime::resolve_machine_identity(app, true));

    kasumi::test::write_text(app / "machine.id", std::string(32, '0') + "\n");
    EXPECT_FALSE(kasumi::runtime::resolve_machine_identity(app, false));
    EXPECT_FALSE(kasumi::runtime::resolve_machine_identity(app, true));

    std::filesystem::remove(app / "machine.id");
    kasumi::test::write_text(
        app / "target.txt", "0123456789abcdef0123456789abcdef\n");
    std::error_code ec;
    std::filesystem::create_symlink(app / "target.txt", app / "machine.id", ec);
    if (!ec) {
        const auto sym_res =
            kasumi::runtime::resolve_machine_identity(app, false);
        ASSERT_FALSE(sym_res.has_value());
        EXPECT_EQ(sym_res.error().code, kasumi::runtime::ErrorCode::PathEscape);
    }
}

} // namespace
