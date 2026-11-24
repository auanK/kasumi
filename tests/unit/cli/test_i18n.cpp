#include "cli/i18n.hpp"
#include "cli/i18n_embedded.hpp"

#include <gtest/gtest.h>
#include <string_view>

using namespace kasumi::cli::i18n;

TEST(CliI18nTest, DefaultLanguageIsEnglish) {
    set_language(Language::English);
    EXPECT_EQ(current_language(), Language::English);
    EXPECT_EQ(tr(Key::LabelError), "[ERROR]");
    EXPECT_EQ(tr(Key::LabelOk), "[OK]");
    EXPECT_EQ(tr(Key::SyncCompleted), "Synchronization completed.");
    EXPECT_EQ(tr(Key::SyncInProgress), "Synchronizing...");
    EXPECT_EQ(tr(Key::SyncStageObserving),
              "[1/5] Observing local and remote state...");
    EXPECT_EQ(tr(Key::SyncStageCalculating), "[2/5] Calculating changes...");
    EXPECT_EQ(tr(Key::SyncEverythingInSync), "Everything in sync.");
    EXPECT_EQ(tr(Key::SyncStageApplying), "[3/5] Applying changes...");
    EXPECT_EQ(tr(Key::SyncStagePublishing), "[4/5] Publishing new state...");
    EXPECT_EQ(tr(Key::SyncStageFinalizing), "[5/5] Finalizing...");
    EXPECT_EQ(tr(Key::PlanStageObserving),
              "[1/2] Observing local and remote state...");
    EXPECT_EQ(tr(Key::PlanStageCalculating), "[2/2] Calculating changes...");
    EXPECT_EQ(format(Key::SyncPlanOmittedSingular, 1), "1 more item");
    EXPECT_EQ(format(Key::SyncPlanOmittedPlural, 5), "5 more items");
    EXPECT_EQ(format(Key::SyncPendingSingular, 1),
              "1 file is waiting for unavailable remote content.");
    EXPECT_NE(tr(Key::HelpText).find("sync <profile> --initial"),
              std::string_view::npos);
    EXPECT_NE(tr(Key::HelpText).find("repack <profile>"),
              std::string_view::npos);
}

TEST(CliI18nTest, SwitchingToPortugueseUpdatesStrings) {
    set_language(Language::Portuguese);
    EXPECT_EQ(current_language(), Language::Portuguese);
    EXPECT_EQ(tr(Key::LabelError), "[ERRO]");
    EXPECT_EQ(tr(Key::LabelOk), "[OK]");
    EXPECT_EQ(tr(Key::SyncCompleted), "Sincronização concluída.");
    EXPECT_EQ(tr(Key::SyncInProgress), "Sincronizando...");
    EXPECT_EQ(tr(Key::SyncStageObserving),
              "[1/5] Observando estado local e remoto...");
    EXPECT_EQ(tr(Key::SyncStageCalculating), "[2/5] Calculando alterações...");
    EXPECT_EQ(tr(Key::SyncEverythingInSync), "Tudo sincronizado.");
    EXPECT_EQ(tr(Key::SyncStageApplying), "[3/5] Aplicando alterações...");
    EXPECT_EQ(tr(Key::SyncStagePublishing), "[4/5] Publicando novo estado...");
    EXPECT_EQ(tr(Key::SyncStageFinalizing), "[5/5] Finalizando...");
    EXPECT_EQ(tr(Key::PlanStageObserving),
              "[1/2] Observando estado local e remoto...");
    EXPECT_EQ(tr(Key::PlanStageCalculating), "[2/2] Calculando alterações...");
    EXPECT_EQ(format(Key::SyncPlanOmittedSingular, 1), "mais 1 item");
    EXPECT_EQ(format(Key::SyncPlanOmittedPlural, 5), "mais 5 itens");
    EXPECT_EQ(format(Key::SyncPendingPlural, 2),
              "2 arquivos aguardam conteúdo remoto indisponível.");
    EXPECT_NE(tr(Key::HelpText).find("sync <perfil> --initial"),
              std::string_view::npos);
    EXPECT_NE(tr(Key::HelpText).find("repack <perfil>"),
              std::string_view::npos);
    set_language(Language::English);
}

TEST(CliI18nTest, ParseLanguageRecognizesVariantsAndFallsBackToEnglish) {
    EXPECT_EQ(parse_language("en"), Language::English);
    EXPECT_EQ(parse_language("en-US"), Language::English);
    EXPECT_EQ(parse_language("english"), Language::English);
    EXPECT_EQ(parse_language("pt"), Language::Portuguese);
    EXPECT_EQ(parse_language("pt-BR"), Language::Portuguese);
    EXPECT_EQ(parse_language("pt_BR"), Language::Portuguese);
    EXPECT_EQ(parse_language("pt-br"), Language::Portuguese);
    EXPECT_EQ(parse_language("portuguese"), Language::Portuguese);
    EXPECT_EQ(parse_language("es"), Language::English);
    EXPECT_EQ(parse_language("ja"), Language::English);
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

    set_language(Language::English);
}

TEST(CliI18nTest, ExtractsStandaloneLanguageFlagPrefix) {
    char arg0[] = "kasumi";
    char arg1[] = "--lang";
    char arg2[] = "pt";
    char* argv[] = {arg0, arg1, arg2};

    const auto sanitized = extract_language_argument(3, argv);
    EXPECT_EQ(current_language(), Language::Portuguese);
    ASSERT_EQ(sanitized.size(), 1U);
    EXPECT_EQ(sanitized[0], "kasumi");

    set_language(Language::English);
}

TEST(CliI18nTest, AllKeysHaveValidTranslations) {
    constexpr std::size_t count =
        static_cast<std::size_t>(Key::DiagnosticsProfileDaemon) + 1;
    ASSERT_EQ(count, embedded::KEY_COUNT);
    for (const Language lang : {Language::English, Language::Portuguese}) {
        set_language(lang);
        for (std::size_t i = 0; i < count; ++i) {
            const auto text = tr(static_cast<Key>(i));
            EXPECT_FALSE(text.empty())
                << "Key " << i << " is empty in language "
                << language_code(lang);
        }
    }
    set_language(Language::English);
}
