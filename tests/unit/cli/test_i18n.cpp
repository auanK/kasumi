#include "cli/i18n.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#if defined(_WIN32)
#include "kasumi/test/scoped_environment.hpp"
#endif

using namespace kasumi::cli::i18n;

TEST(CliI18nTest, DefaultLanguageIsEnglish) {
    set_language(Language::English);
    EXPECT_EQ(current_language(), Language::English);
    EXPECT_EQ(tr(Key::LabelError), "[ERROR]");
    EXPECT_EQ(tr(Key::LabelOk), "[OK]");
    EXPECT_EQ(tr(Key::SyncCompleted), "Synchronization completed.");
    EXPECT_EQ(tr(Key::SyncInProgress), "Synchronizing...");
}

TEST(CliI18nTest, SwitchingToPortugueseUpdatesStrings) {
    set_language(Language::Portuguese);
    EXPECT_EQ(current_language(), Language::Portuguese);
    EXPECT_EQ(tr(Key::LabelError), "[ERRO]");
    EXPECT_EQ(tr(Key::LabelOk), "[OK]");
    EXPECT_EQ(tr(Key::SyncCompleted), "Sincronização concluída.");
    EXPECT_EQ(tr(Key::SyncInProgress), "Sincronizando...");
    set_language(Language::English); // Restore default
}

TEST(CliI18nTest, ParseLanguageRecognizesVariants) {
    EXPECT_EQ(parse_language("en"), Language::English);
    EXPECT_EQ(parse_language("en-US"), Language::English);
    EXPECT_EQ(parse_language("english"), Language::English);
    EXPECT_EQ(parse_language("pt"), Language::Portuguese);
    EXPECT_EQ(parse_language("pt-BR"), Language::Portuguese);
    EXPECT_EQ(parse_language("pt_BR"), Language::Portuguese);
    EXPECT_EQ(parse_language("pt-br"), Language::Portuguese);
    EXPECT_EQ(parse_language("portuguese"), Language::Portuguese);
    EXPECT_EQ(parse_language("es"), Language::Custom);
    EXPECT_EQ(parse_language("ja"), Language::Custom);
}

TEST(CliI18nTest, ExtractsLanguageFlagCorrectly) {
    char arg0[] = "kasumi";
    char arg1[] = "--lang";
    char arg2[] = "pt";
    char arg3[] = "sync";
    char arg4[] = "Pictures";
    char* argv[] = {arg0, arg1, arg2, arg3, arg4};

    const auto sanitized = extract_language_argument(5, argv);
    EXPECT_EQ(current_language(), Language::Portuguese);
    ASSERT_EQ(sanitized.size(), 3U);
    EXPECT_EQ(sanitized[0], "kasumi");
    EXPECT_EQ(sanitized[1], "sync");
    EXPECT_EQ(sanitized[2], "Pictures");

    set_language(Language::English); // Restore default
}

TEST(CliI18nTest, ExtractsInlineLanguageFlag) {
    char arg0[] = "kasumi";
    char arg1[] = "--lang=pt";
    char arg2[] = "status";
    char* argv[] = {arg0, arg1, arg2};

    const auto sanitized = extract_language_argument(3, argv);
    EXPECT_EQ(current_language(), Language::Portuguese);
    ASSERT_EQ(sanitized.size(), 2U);
    EXPECT_EQ(sanitized[0], "kasumi");
    EXPECT_EQ(sanitized[1], "status");

    set_language(Language::English); // Restore default
}

TEST(CliI18nTest, AllKeysHaveValidTranslations) {
    const auto test_catalog = [](Language lang) {
        set_language(lang);
        constexpr std::size_t count =
            static_cast<std::size_t>(Key::WizardConfigReadFailed) + 1;
        for (std::size_t i = 0; i < count; ++i) {
            const auto text = tr(static_cast<Key>(i));
            EXPECT_FALSE(text.empty())
                << "Key " << i << " is empty in language "
                << language_code(lang);
        }
    };

    test_catalog(Language::English);
    test_catalog(Language::Portuguese);
    set_language(Language::English); // Restore default
}

TEST(CliI18nTest,
     CustomJsonCatalogOverridesSpecifiedKeysAndFallsBackToEnglish) {
    constexpr const char* CUSTOM_SPANISH_JSON = R"json({
        "labels": {
            "error": "[ERROR_ES]"
        },
        "sync": {
            "completed": "Sincronización completada."
        }
    })json";

    ASSERT_TRUE(load_custom_catalog(CUSTOM_SPANISH_JSON));
    EXPECT_EQ(current_language(), Language::Custom);
    // Overridden keys
    EXPECT_EQ(tr(Key::LabelError), "[ERROR_ES]");
    EXPECT_EQ(tr(Key::SyncCompleted), "Sincronización completada.");
    // Fallback to English for unspecified keys
    EXPECT_EQ(tr(Key::LabelOk), "[OK]");
    EXPECT_EQ(tr(Key::SyncInProgress), "Synchronizing...");

    set_language(Language::English); // Restore default
}

#if defined(_WIN32)
TEST(CliI18nTest, ExternalLocaleDiscoveryUnderUnicodeAppData) {
    const auto temp_root = std::filesystem::temp_directory_path() /
                           u8"kasumi_i18n_usuário-João-日本";
    std::filesystem::create_directories(temp_root / "kasumi" / "locales");

    const auto locale_file = temp_root / "kasumi" / "locales" / "fr.json";
    {
        std::ofstream file(locale_file);
        file << R"json({
            "labels": {
                "error": "[ERREUR_FR]"
            },
            "sync": {
                "completed": "Synchronisation terminee."
            }
        })json";
    }

    {
        const auto env = kasumi::test::scoped_windows_environment_variable(
            L"APPDATA", temp_root.native());

        set_language("fr");
        EXPECT_EQ(current_language(), Language::Custom);
        EXPECT_EQ(tr(Key::LabelError), "[ERREUR_FR]");
        EXPECT_EQ(tr(Key::SyncCompleted), "Synchronisation terminee.");

        set_language(Language::English); // Restore default
    }

    std::error_code ec;
    std::filesystem::remove_all(temp_root, ec);
}
#endif
