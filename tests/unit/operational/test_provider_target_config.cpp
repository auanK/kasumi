#include "../../operational/provider_target_config.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace config = kasumi::operational::provider_target_config;

constexpr std::string_view two_targets = R"toml(
[[targets]]
id = "drive-test"
provider_id = "drive-test"
remote = "remote-a"
authorized_parent = "remote-a:integration-tests"

[[targets]]
id = "sftp-test"
provider_id = "sftp-test"
remote = "remote-b"
authorized_parent = "remote-b:certification-parent"
)toml";

std::filesystem::path write_config(const std::filesystem::path& path,
                                   std::string_view contents) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << contents;
    return path;
}

TEST(ProviderTargetConfigTest, ParsesMultipleTargetsAndSelectsExactId) {
    auto workspace = kasumi::test::make_temp_workspace("provider-config-valid");
    const auto path = kasumi::test::workspace_path(workspace, "targets.toml");
    ASSERT_TRUE(write_config(path, two_targets).string().size() > 0);

    const auto loaded = config::load_config(path);
    ASSERT_TRUE(loaded.has_value()) << loaded.error();
    ASSERT_EQ(loaded->targets.size(), 2U);

    const auto selected = config::select_target(*loaded, "sftp-test");
    ASSERT_TRUE(selected.has_value()) << selected.error();
    EXPECT_EQ(selected->provider_id, "sftp-test");
    EXPECT_EQ(selected->remote, "remote-b");
    EXPECT_EQ(selected->authorized_parent, "remote-b:certification-parent");

    const auto unknown = config::select_target(*loaded, "sftp");
    EXPECT_FALSE(unknown.has_value());
}

TEST(ProviderTargetConfigTest, RejectsMissingFileAndMalformedToml) {
    auto workspace =
        kasumi::test::make_temp_workspace("provider-config-malformed");
    const auto missing =
        kasumi::test::workspace_path(workspace, "missing.toml");
    EXPECT_FALSE(config::load_config(missing).has_value());

    const auto malformed =
        kasumi::test::workspace_path(workspace, "broken.toml");
    write_config(malformed, "[[targets]\nid = [\n");
    EXPECT_FALSE(config::load_config(malformed).has_value());
}

TEST(ProviderTargetConfigTest,
     RejectsDuplicateIdsMissingFieldsAndUnsafeTargets) {
    const std::vector<std::string> invalid_configs = {
        "",
        "targets = []\n",
        "unexpected = true\n",
        "[[targets]]\nid=\"same\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:one\"\n"
        "[[targets]]\nid=\"same\"\nprovider_id=\"p\"\nremote=\"remote-"
        "b\"\nauthorized_parent=\"remote-b:two\"\n",
        "[[targets]]\nid=\"one\"\nremote=\"remote-a\"\nauthorized_parent="
        "\"remote-a:one\"\n",
        "[[targets]]\nid=\"\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:one\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:one\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"\"\nauthorized_"
        "parent=\"remote-a:one\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-b:one\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:one/\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:.\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:../escape\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:one//two\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:\\one\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:/home/test/parent\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote/"
        "a\"\nauthorized_parent=\"remote/a:one\"\n",
        "[[targets]]\nid=\"one\"\nprovider_id=\"p\"\nremote=\"remote-"
        "a\"\nauthorized_parent=\"remote-a:one\"\nextra=\"value\"\n",
    };

    auto workspace =
        kasumi::test::make_temp_workspace("provider-config-invalid");
    const auto path = kasumi::test::workspace_path(workspace, "targets.toml");
    for (const auto& contents : invalid_configs) {
        write_config(path, contents);
        EXPECT_FALSE(config::load_config(path).has_value()) << contents;
    }
}

TEST(ProviderTargetConfigTest, AuthorizationUsesExactConfiguredParent) {
    const config::LiveTargetAuthorization authorization{
        .authorized_parent = "remote-a:integration-tests",
    };
    EXPECT_TRUE(config::authorized_live_parent(authorization,
                                               "remote-a:integration-tests"));
    for (const auto requested : {
             "remote-a:integration-tests/child",
             "remote-a:",
             "remote-a:other",
             "remote-b:integration-tests",
             "remote-a:../escape",
         }) {
        EXPECT_FALSE(config::authorized_live_parent(authorization, requested))
            << requested;
    }
}

TEST(ProviderTargetConfigCliTest, LocalTargetDoesNotNeedLiveConfig) {
    const std::vector<std::string_view> args = {
        "kasumi_provider_certification", "--target", "local"};
    const auto parsed = config::parse_target_selection_arguments(args);
    ASSERT_TRUE(parsed.has_value()) << parsed.error();
    const auto selected = config::resolve_target(*parsed);
    ASSERT_TRUE(selected.has_value()) << selected.error();
    EXPECT_FALSE(selected->has_value());
}

TEST(ProviderTargetConfigCliTest, RcloneTargetRequiresConfigAndTargetId) {
    const std::vector<std::string_view> no_config = {
        "kasumi_provider_certification",
        "--target",
        "rclone",
        "--target-id",
        "sftp-test"};
    const auto parsed_no_config =
        config::parse_target_selection_arguments(no_config);
    ASSERT_TRUE(parsed_no_config.has_value());
    EXPECT_FALSE(config::resolve_target(*parsed_no_config).has_value());

    const std::vector<std::string_view> no_id = {
        "kasumi_provider_certification",
        "--target",
        "rclone",
        "--config",
        "targets.toml"};
    const auto parsed_no_id = config::parse_target_selection_arguments(no_id);
    ASSERT_TRUE(parsed_no_id.has_value());
    EXPECT_FALSE(config::resolve_target(*parsed_no_id).has_value());
}

TEST(ProviderTargetConfigCliTest, ResolvesOnlyExactConfiguredTarget) {
    auto workspace = kasumi::test::make_temp_workspace("provider-config-cli");
    const auto path = kasumi::test::workspace_path(workspace, "targets.toml");
    write_config(path, two_targets);
    const auto path_text = path.string();
    const std::vector<std::string_view> args = {"kasumi_provider_certification",
                                                "--target",
                                                "rclone",
                                                "--config",
                                                path_text,
                                                "--target-id",
                                                "sftp-test"};
    const auto parsed = config::parse_target_selection_arguments(args);
    ASSERT_TRUE(parsed.has_value()) << parsed.error();
    const auto selected = config::resolve_target(*parsed);
    ASSERT_TRUE(selected.has_value()) << selected.error();
    ASSERT_TRUE(selected->has_value());
    EXPECT_EQ((*selected)->provider_id, "sftp-test");
    EXPECT_EQ((*selected)->remote, "remote-b");
    EXPECT_EQ((*selected)->authorized_parent, "remote-b:certification-parent");

    auto unknown = *parsed;
    unknown.target_id = "sftp";
    EXPECT_FALSE(config::resolve_target(unknown).has_value());
}

TEST(ProviderTargetConfigCliTest, MissingFileAndRawOverridesFailClosed) {
    config::TargetSelectionArguments missing_file{
        .target_kind = "rclone",
        .config_path = "does-not-exist.toml",
        .target_id = "sftp-test",
    };
    EXPECT_FALSE(config::resolve_target(missing_file).has_value());

    for (const auto raw_option : {"--provider-id",
                                  "--remote",
                                  "--remote-parent",
                                  "--authorized-parent"}) {
        const std::vector<std::string_view> args = {
            "kasumi_provider_certification",
            "--target",
            "rclone",
            "--config",
            "targets.toml",
            "--target-id",
            "sftp-test",
            raw_option,
            "raw-value"};
        EXPECT_FALSE(config::parse_target_selection_arguments(args).has_value())
            << raw_option;
    }
}

} // namespace
