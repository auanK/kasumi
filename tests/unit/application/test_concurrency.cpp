#include "application/concurrency.hpp"

#include <cstdlib>
#include <gtest/gtest.h>

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

} // namespace
