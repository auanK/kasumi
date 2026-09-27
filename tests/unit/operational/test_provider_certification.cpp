#include "provider_certification_support.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

namespace {

using namespace kasumi::operational::provider_certification;

TEST(ProviderCertificationTargetTest, OwnsUniqueChildAndRejectsEscape) {
    const auto parent = std::filesystem::temp_directory_path();
    auto first = create_local_target(parent);
    auto second = create_local_target(parent);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->root, second->root);
    EXPECT_EQ(first->root.parent_path(), first->authorized_parent);

    EXPECT_FALSE(target_path(*first, "../escape").has_value());
    EXPECT_FALSE(target_path(*first, first->root / "absolute").has_value());
    EXPECT_TRUE(target_path(*first, "owned/file").has_value());

    const auto clean_first = cleanup_local_target(*first);
    ASSERT_TRUE(clean_first.has_value()) << clean_first.error();
    const auto clean_second = cleanup_local_target(*second);
    ASSERT_TRUE(clean_second.has_value()) << clean_second.error();
    EXPECT_FALSE(std::filesystem::exists(first->root));
}

TEST(ProviderCertificationTargetTest, RefusesForeignOwnershipMarker) {
    auto target = create_local_target(std::filesystem::temp_directory_path());
    ASSERT_TRUE(target.has_value());
    const auto marker = target->root / ".kasumi-certification-owner";
    {
        std::ofstream output(marker, std::ios::binary | std::ios::trunc);
        output << "foreign";
    }
    const auto refused = cleanup_local_target(*target);
    ASSERT_FALSE(refused.has_value());
    EXPECT_TRUE(std::filesystem::is_directory(target->root));
    {
        std::ofstream output(marker, std::ios::binary | std::ios::trunc);
        output << target->ownership_token;
    }
    const auto cleanup = cleanup_local_target(*target);
    ASSERT_TRUE(cleanup.has_value()) << cleanup.error();
}

TEST(ProviderCertificationTargetTest, RefusesReparseAndPathReplacement) {
    auto target = create_local_target(std::filesystem::temp_directory_path());
    auto outside = create_local_target(std::filesystem::temp_directory_path());
    ASSERT_TRUE(target.has_value());
    ASSERT_TRUE(outside.has_value());
    const auto link = target->root / "outside-link";
    std::error_code error;
    std::filesystem::create_directory_symlink(outside->root, link, error);
    if (error) {
        const auto cleanup_a = cleanup_local_target(*target);
        const auto cleanup_b = cleanup_local_target(*outside);
        EXPECT_TRUE(cleanup_a.has_value());
        EXPECT_TRUE(cleanup_b.has_value());
    } else {
        EXPECT_FALSE(target_path(*target, "outside-link/file").has_value());
        const auto refused_link = cleanup_local_target(*target);
        EXPECT_FALSE(refused_link.has_value());
        std::filesystem::remove(link, error);
        ASSERT_FALSE(error) << error.message();
        ASSERT_TRUE(cleanup_local_target(*target).has_value());
        ASSERT_TRUE(cleanup_local_target(*outside).has_value());
    }

    auto replaced = create_local_target(std::filesystem::temp_directory_path());
    ASSERT_TRUE(replaced.has_value());
    const auto original = replaced->root;
    const auto parked =
        original.parent_path() / (original.filename().string() + "-owned");
    std::filesystem::rename(original, parked);
    ASSERT_TRUE(std::filesystem::create_directory(original));
    const auto refused_replacement = cleanup_local_target(*replaced);
    EXPECT_FALSE(refused_replacement.has_value());
    std::filesystem::remove(original);
    std::filesystem::rename(parked, original);
    ASSERT_TRUE(cleanup_local_target(*replaced).has_value());
}

TEST(ProviderCertificationReportTest, DerivesCorrectnessAndRetainsEvidence) {
    Report report;
    report.cleanup = "CLEANED";
    report.capabilities.push_back(
        {.name = "physical_hash", .status = CapabilityStatus::Unsupported});
    report.scenarios = {
        {.name = "first",
         .status = ScenarioStatus::Pass,
         .requests = {{"get", 2}}},
        {.name = "gc-lifecycle", .status = ScenarioStatus::NotRun},
    };
    EXPECT_EQ(derive_status(report), "PASS");
    const auto json = to_json(report);
    EXPECT_EQ(json["scenarios"][0]["name"], "first");
    EXPECT_EQ(json["scenarios"][0]["requests"]["get"], 2);

    report.scenarios[0].status = ScenarioStatus::Fail;
    EXPECT_EQ(derive_status(report), "FAIL");
    report.scenarios[0].status = ScenarioStatus::Pass;
    report.cleanup = "FAILED";
    EXPECT_EQ(derive_status(report), "FAIL");
}

TEST(ProviderCertificationTest, LocalReferenceScenariosPass) {
    auto target = create_local_target(std::filesystem::temp_directory_path());
    ASSERT_TRUE(target.has_value());
    auto report = run_local_certification(target->root);
    EXPECT_EQ(report.scenarios.size(), 12U) << to_json(report).dump(2);
    for (const auto& scenario : report.scenarios) {
        EXPECT_NE(scenario.status, ScenarioStatus::Fail)
            << scenario.name << ": " << to_json(report).dump(2);
    }
    auto cleanup = cleanup_local_target(*target);
    ASSERT_TRUE(cleanup.has_value()) << cleanup.error();
    report.cleanup = "CLEANED";
    report.scenarios.push_back(
        {.name = "cleanup", .status = ScenarioStatus::Pass});
    report.status = derive_status(report);
    EXPECT_EQ(report.status, "PASS") << to_json(report).dump(2);
}

} // namespace
