#include "platform/clock.hpp"
#include "platform/machine.hpp"

#include <gtest/gtest.h>
#include <regex>
#include <string>

namespace {

namespace clock_util = kasumi::platform::clock;
namespace machine_util = kasumi::platform::machine;

TEST(PlatformClockTest, FormatsUtcTimestampsAndInvalidValues) {
    EXPECT_EQ(clock_util::format_utc_timestamp(0), "-");
    EXPECT_EQ(clock_util::format_utc_timestamp(-5), "-");
    EXPECT_EQ(clock_util::format_local_timestamp(0), "-");
    EXPECT_EQ(clock_util::format_local_timestamp(-1), "-");

    // 1700000000 = 2023-11-14 22:13:20 UTC
    EXPECT_EQ(clock_util::format_utc_timestamp(1700000000, true),
              "2023-11-14 22:13:20 +00:00");
    EXPECT_EQ(clock_util::format_utc_timestamp(1700000000, false),
              "2023-11-14 22:13 +00:00");
}

TEST(PlatformClockTest, LocalTimestampIncludesExplicitOffset) {
    const auto full = clock_util::format_local_timestamp(1700000000, true);
    EXPECT_TRUE(std::regex_match(
        full,
        std::regex(R"(^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{2}:\d{2}$)")))
        << full;

    const auto short_fmt =
        clock_util::format_local_timestamp(1700000000, false);
    EXPECT_TRUE(std::regex_match(
        short_fmt,
        std::regex(R"(^\d{4}-\d{2}-\d{2} \d{2}:\d{2} [+-]\d{2}:\d{2}$)")))
        << short_fmt;
}

TEST(PlatformMachineTest, SanitizesNamesAndTruncatesUtf8Safely) {
    EXPECT_EQ(machine_util::sanitize_machine_name(""), "unknown");
    EXPECT_EQ(machine_util::sanitize_machine_name("  \t\n\x7f  "), "unknown");
    EXPECT_EQ(machine_util::sanitize_machine_name("  PC-Casa\r\n "), "PC-Casa");
    EXPECT_EQ(machine_util::sanitize_machine_name("node\x01\x02name"),
              "node name");

    // Repeat 4-byte emoji (35 * 4 = 140 bytes) -> truncated on boundary <= 128.
    std::string long_utf8;
    for (int i = 0; i < 35; ++i) {
        long_utf8 += "\xF0\x9F\x8C\xB8"; // 4-byte UTF-8 sequence
    }
    const auto truncated = machine_util::sanitize_machine_name(long_utf8);
    EXPECT_LE(truncated.size(), machine_util::maximum_machine_name_bytes);
    EXPECT_EQ(truncated.size(), 128U);
    EXPECT_EQ(truncated.size() % 4U, 0U);
}

TEST(PlatformMachineTest, QueriesNonEmptySanitizedHostName) {
    const auto name = machine_util::host_name();
    EXPECT_FALSE(name.empty());
    EXPECT_LE(name.size(), machine_util::maximum_machine_name_bytes);
    EXPECT_EQ(machine_util::sanitize_machine_name(name), name);
}

} // namespace
