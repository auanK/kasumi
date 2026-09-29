#include "../../operational/gc_live_phase11_support.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <gtest/gtest.h>

namespace {

namespace phase11 = kasumi::operational::phase11;
namespace transport = kasumi::transport;
namespace target_config = kasumi::operational::provider_target_config;

TEST(Phase11GuardrailTest, AuthorizationIsExplicitAndExact) {
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

TEST(Phase11GuardrailTest, DisallowedRootValidation) {
    EXPECT_FALSE(phase11::smoke::parse_remote_parent("remote-a:").has_value());
    EXPECT_FALSE(phase11::smoke::parse_remote_parent("remote-a").has_value());
    EXPECT_FALSE(phase11::smoke::parse_remote_parent("").has_value());
    EXPECT_TRUE(phase11::smoke::parse_remote_parent(
                    "remote-a:integration-tests").has_value());
}

TEST(Phase11GuardrailTest, GenerateBenchmarkChildNonceValidation) {
    auto valid = phase11::generate_benchmark_child("0123456789abcdef0123456789abcdef");
    ASSERT_TRUE(valid.has_value());
    EXPECT_EQ(*valid, "kasumi-gc-benchmark-0123456789abcdef0123456789abcdef");

    auto too_short = phase11::generate_benchmark_child("1234");
    EXPECT_FALSE(too_short.has_value());

    auto invalid_hex = phase11::generate_benchmark_child("0123456789abcdefghij0123456789");
    EXPECT_FALSE(invalid_hex.has_value());
}

TEST(Phase11SafetyTest, DryRunRefusesExecutionWithoutExecuteLiveFlag) {
    phase11::Phase11Config config{
        .remote_parent = "remote-a:integration-tests",
        .authorization = {
            .authorized_parent = "remote-a:integration-tests"},
        .execute_live = false
    };
    phase11::Phase11RunReport report;
    auto status = phase11::run_capability_test(config, report);
    EXPECT_EQ(status, phase11::CapabilityStatus::Refused);
    EXPECT_EQ(report.status, "REFUSED");
    EXPECT_NE(report.error_message.find("dry run safety"), std::string::npos);

    auto trial_report = phase11::run_benchmark_trial(config);
    EXPECT_EQ(trial_report.status, "REFUSED");
    EXPECT_NE(trial_report.error_message.find("dry run safety"), std::string::npos);
}

TEST(Phase11SafetyTest, RefusesUnauthorizedParentEvenWithLiveFlag) {
    phase11::Phase11Config config{
        .remote_parent = "remote-a:unauthorized-vault",
        .authorization = {
            .authorized_parent = "remote-a:integration-tests"},
        .execute_live = true
    };
    phase11::Phase11RunReport report;
    auto status = phase11::run_capability_test(config, report);
    EXPECT_EQ(status, phase11::CapabilityStatus::Refused);
    EXPECT_EQ(report.status, "REFUSED");
    EXPECT_NE(report.error_message.find("not authorized"), std::string::npos);

    auto trial_report = phase11::run_benchmark_trial(config);
    EXPECT_EQ(trial_report.status, "REFUSED");
    EXPECT_NE(trial_report.error_message.find("not authorized"), std::string::npos);
}

} // namespace
