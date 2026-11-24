#include "application/concurrency.hpp"
#include "application/credentials.hpp"
#include "platform/cancellation.hpp"

#include <atomic>
#include <cstdlib>
#include <gtest/gtest.h>
#include <stop_token>
#include <thread>
#include <vector>

namespace {

void set_env(const char* name, const char* value) {
#if defined(_WIN32)
    if (value == nullptr) {
        _putenv_s(name, "");
    } else {
        _putenv_s(name, value);
    }
#else
    if (value == nullptr) {
        unsetenv(name);
    } else {
        setenv(name, value, 1);
    }
#endif
}

class ConcurrencyTest : public ::testing::Test {
protected:
    void SetUp() override {
        original_val_ = std::getenv("KASUMI_CONTENT_CONCURRENCY");
    }

    void TearDown() override {
        set_env("KASUMI_CONTENT_CONCURRENCY", original_val_);
    }

private:
    const char* original_val_ = nullptr;
};

TEST_F(ConcurrencyTest, DefaultsToEightWhenUnset) {
    set_env("KASUMI_CONTENT_CONCURRENCY", nullptr);
    EXPECT_EQ(kasumi::application::content_concurrency(), 8U);
}

TEST_F(ConcurrencyTest, ParsesValidValues) {
    set_env("KASUMI_CONTENT_CONCURRENCY", "1");
    EXPECT_EQ(kasumi::application::content_concurrency(), 1U);

    set_env("KASUMI_CONTENT_CONCURRENCY", "4");
    EXPECT_EQ(kasumi::application::content_concurrency(), 4U);

    set_env("KASUMI_CONTENT_CONCURRENCY", "8");
    EXPECT_EQ(kasumi::application::content_concurrency(), 8U);

    set_env("KASUMI_CONTENT_CONCURRENCY", "16");
    EXPECT_EQ(kasumi::application::content_concurrency(), 16U);
}

TEST_F(ConcurrencyTest, CapsAtMaximumSixteen) {
    set_env("KASUMI_CONTENT_CONCURRENCY", "32");
    EXPECT_EQ(kasumi::application::content_concurrency(), 16U);

    set_env("KASUMI_CONTENT_CONCURRENCY", "1000");
    EXPECT_EQ(kasumi::application::content_concurrency(), 16U);
}

TEST_F(ConcurrencyTest, FallsBackToDefaultOnInvalidOrZero) {
    set_env("KASUMI_CONTENT_CONCURRENCY", "0");
    EXPECT_EQ(kasumi::application::content_concurrency(), 8U);

    set_env("KASUMI_CONTENT_CONCURRENCY", "invalid");
    EXPECT_EQ(kasumi::application::content_concurrency(), 8U);

    set_env("KASUMI_CONTENT_CONCURRENCY", "-4");
    EXPECT_EQ(kasumi::application::content_concurrency(), 8U);

    set_env("KASUMI_CONTENT_CONCURRENCY", "8extra");
    EXPECT_EQ(kasumi::application::content_concurrency(), 8U);
}

TEST_F(ConcurrencyTest, ResolveAndScopeContentConcurrencyPrecedence) {
    set_env("KASUMI_CONTENT_CONCURRENCY", "6");
    EXPECT_EQ(kasumi::application::resolve_content_concurrency(std::nullopt,
                                                               std::nullopt),
              6U);
    EXPECT_EQ(
        kasumi::application::resolve_content_concurrency(std::nullopt, 4U), 4U);
    EXPECT_EQ(kasumi::application::resolve_content_concurrency(2U, 4U), 2U);

    {
        kasumi::application::ScopedContentConcurrency outer{3U};
        EXPECT_EQ(kasumi::application::content_concurrency(), 3U);
        EXPECT_EQ(kasumi::application::current_content_concurrency_override(),
                  std::optional<std::size_t>{3U});
        {
            kasumi::application::ScopedContentConcurrency inner{5U};
            EXPECT_EQ(kasumi::application::content_concurrency(), 5U);
        }
        EXPECT_EQ(kasumi::application::content_concurrency(), 3U);
    }
    EXPECT_EQ(kasumi::application::content_concurrency(), 6U);
}

TEST(StopTokenTest, ScopedStopTokenIsolatesThreadsAndPropagatesToParallelWork) {
    kasumi::platform::cancellation::reset();
    EXPECT_FALSE(kasumi::platform::cancellation::requested());

    std::stop_source src_a;
    std::stop_source src_b;
    std::atomic<bool> a_cancelled{false};
    std::atomic<bool> b_cancelled{false};
    std::atomic<bool> a_workers_cancelled{false};

    std::jthread t_b([&] {
        kasumi::platform::cancellation::ScopedStopToken scope{
            src_b.get_token()};
        b_cancelled.store(kasumi::platform::cancellation::requested());
    });
    t_b.join();
    EXPECT_FALSE(b_cancelled.load());

    {
        kasumi::platform::cancellation::ScopedStopToken scope{
            src_a.get_token()};
        src_a.request_stop();
        a_cancelled.store(kasumi::platform::cancellation::requested());

        std::vector<std::uint8_t> worker_seen(4, 0U);
        kasumi::application::parallel_for_indexed(
            worker_seen.size(), 4U, [&](std::size_t i) {
                worker_seen[i] =
                    kasumi::platform::cancellation::requested() ? 1U : 0U;
            });
        a_workers_cancelled.store(worker_seen[0] == 1U &&
                                  worker_seen[1] == 1U &&
                                  worker_seen[2] == 1U && worker_seen[3] == 1U);
    }
    EXPECT_TRUE(a_cancelled.load());
    EXPECT_TRUE(a_workers_cancelled.load());
    // Prior global state remains unaffected once ScopedStopToken exits.
    EXPECT_FALSE(kasumi::platform::cancellation::requested());
}

TEST(CredentialsMemoryTest, MasterKeyBytesZeroesSourceOnMoveAndWipe) {
    std::array<std::uint8_t, 32> raw{};
    for (std::size_t i = 0; i < raw.size(); ++i) {
        raw[i] = static_cast<std::uint8_t>(i + 1U);
    }
    kasumi::application::MasterKeyBytes first{raw};
    kasumi::application::MasterKeyBytes moved{std::move(first)};
    for (std::uint8_t b : first.bytes) {
        EXPECT_EQ(b, 0U);
    }
    EXPECT_EQ(moved.bytes, raw);

    kasumi::application::Credentials creds{moved};
    kasumi::application::wipe_credentials(creds);
    const auto* wiped =
        std::get_if<kasumi::application::MasterKeyBytes>(&creds);
    ASSERT_NE(wiped, nullptr);
    for (std::uint8_t b : wiped->bytes) {
        EXPECT_EQ(b, 0U);
    }
}

} // namespace
