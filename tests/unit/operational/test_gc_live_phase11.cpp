#include "../../operational/gc_live_phase11_support.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <gtest/gtest.h>

namespace {

namespace phase11 = kasumi::operational::phase11;
namespace transport = kasumi::transport;

TEST(Phase11GuardrailTest, AuthorizedParentStrictValidation) {
    EXPECT_TRUE(phase11::is_authorized_parent("kasumi:integration-tests"));
    EXPECT_FALSE(phase11::is_authorized_parent("kasumi:"));
    EXPECT_FALSE(phase11::is_authorized_parent("kasumi"));
    EXPECT_FALSE(phase11::is_authorized_parent("kasumi:other-parent"));
    EXPECT_FALSE(phase11::is_authorized_parent("other:integration-tests"));
    EXPECT_FALSE(phase11::is_authorized_parent(""));
}

TEST(Phase11GuardrailTest, DisallowedRootValidation) {
    EXPECT_TRUE(phase11::is_disallowed_root("kasumi:"));
    EXPECT_TRUE(phase11::is_disallowed_root("kasumi"));
    EXPECT_TRUE(phase11::is_disallowed_root(""));
    EXPECT_FALSE(phase11::is_disallowed_root("kasumi:integration-tests"));
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
        .remote_parent = "kasumi:integration-tests",
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
        .remote_parent = "kasumi:unauthorized-vault",
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
