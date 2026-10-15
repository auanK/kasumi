#include "../../operational/gc_live_copy_benchmark_support.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <gtest/gtest.h>

namespace {

namespace gc_live_copy_benchmark = kasumi::operational::gc_live_copy_benchmark;
namespace transport = kasumi::transport;
namespace target_config = kasumi::operational::provider_target_config;

TEST(LiveGcAuthorizationTest, AuthorizationIsExplicitAndExact) {
    const target_config::LiveTargetAuthorization authorization{
        .authorized_parent = "remote-a:integration-tests"};
    EXPECT_TRUE(target_config::authorized_live_parent(
        authorization, "remote-a:integration-tests"));
    EXPECT_FALSE(target_config::authorized_live_parent(
        authorization, "remote-a:integration-tests/child"));
    EXPECT_FALSE(target_config::authorized_live_parent(
        authorization, "remote-a:other-parent"));
    EXPECT_FALSE(target_config::authorized_live_parent(
        authorization, "remote-b:integration-tests"));
}

TEST(LiveGcAuthorizationTest, DisallowedRootValidation) {
    EXPECT_FALSE(gc_live_copy_benchmark::smoke::parse_remote_parent("remote-a:").has_value());
    EXPECT_FALSE(gc_live_copy_benchmark::smoke::parse_remote_parent("remote-a").has_value());
    EXPECT_FALSE(gc_live_copy_benchmark::smoke::parse_remote_parent("").has_value());
    EXPECT_TRUE(
        gc_live_copy_benchmark::smoke::parse_remote_parent("remote-a:integration-tests")
            .has_value());
}

TEST(LiveGcAuthorizationTest, GenerateBenchmarkChildNonceValidation) {
    auto valid =
        gc_live_copy_benchmark::generate_trial_child("0123456789abcdef0123456789abcdef");
    ASSERT_TRUE(valid.has_value());
    EXPECT_EQ(*valid, "kasumi-gc-benchmark-0123456789abcdef0123456789abcdef");

    auto too_short = gc_live_copy_benchmark::generate_trial_child("1234");
    EXPECT_FALSE(too_short.has_value());

    auto invalid_hex =
        gc_live_copy_benchmark::generate_trial_child("0123456789abcdefghij0123456789");
    EXPECT_FALSE(invalid_hex.has_value());
}

TEST(LiveGcSafetyTest, DryRunRefusesExecutionWithoutExecuteLiveFlag) {
    gc_live_copy_benchmark::GcLiveCopyBenchmarkConfig config{
        .remote_parent = "remote-a:integration-tests",
        .authorization = {.authorized_parent = "remote-a:integration-tests"},
        .execute_live = false};
    gc_live_copy_benchmark::GcLiveCopyBenchmarkReport report;
    auto status = gc_live_copy_benchmark::check_copy_capability(config, report);
    EXPECT_EQ(status, gc_live_copy_benchmark::CapabilityStatus::Refused);
    EXPECT_EQ(report.status, "REFUSED");
    EXPECT_NE(report.error_message.find("dry run safety"), std::string::npos);

    auto trial_report = gc_live_copy_benchmark::run_copy_benchmark(config);
    EXPECT_EQ(trial_report.status, "REFUSED");
    EXPECT_NE(trial_report.error_message.find("dry run safety"),
              std::string::npos);
}

TEST(LiveGcSafetyTest, RefusesUnauthorizedParentEvenWithLiveFlag) {
    gc_live_copy_benchmark::GcLiveCopyBenchmarkConfig config{
        .remote_parent = "remote-a:unauthorized-vault",
        .authorization = {.authorized_parent = "remote-a:integration-tests"},
        .execute_live = true};
    gc_live_copy_benchmark::GcLiveCopyBenchmarkReport report;
    auto status = gc_live_copy_benchmark::check_copy_capability(config, report);
    EXPECT_EQ(status, gc_live_copy_benchmark::CapabilityStatus::Refused);
    EXPECT_EQ(report.status, "REFUSED");
    EXPECT_NE(report.error_message.find("not authorized"), std::string::npos);

    auto trial_report = gc_live_copy_benchmark::run_copy_benchmark(config);
    EXPECT_EQ(trial_report.status, "REFUSED");
    EXPECT_NE(trial_report.error_message.find("not authorized"),
              std::string::npos);
}

} // namespace
