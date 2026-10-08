#include "cli/i18n_collision.hpp"

#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>

TEST(CliI18nGeneratorTest, RawStringDelimiterCollisionReconstructsJson) {
    std::ifstream fixture{KASUMI_I18N_COLLISION_FIXTURE_PATH,
                          std::ios::binary};
    ASSERT_TRUE(fixture.is_open());
    const std::string expected{std::istreambuf_iterator<char>{fixture},
                               std::istreambuf_iterator<char>{}};
    ASSERT_NE(expected.find(")kasumi\""), std::string::npos);

    EXPECT_EQ(kasumi::cli::i18n::embedded::reconstructed_en_json(), expected);
    EXPECT_EQ(kasumi::cli::i18n::embedded::reconstructed_pt_br_json(), expected);
}
