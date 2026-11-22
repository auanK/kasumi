#include "application/inspection/result.hpp"
#include "cli/i18n.hpp"
#include "cli/presenter.hpp"
#include "kasumi/test/capture.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"

#include <algorithm>
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <utility>

namespace {

using namespace kasumi::application;
using kasumi::cli::i18n::Language;

struct ScopedLanguage {
    kasumi::cli::i18n::Language previous =
        kasumi::cli::i18n::current_language();

    explicit ScopedLanguage(kasumi::cli::i18n::Language language) {
        kasumi::cli::i18n::set_language(language);
    }

    ~ScopedLanguage() {
        kasumi::cli::i18n::set_language(previous);
    }
};

Response response(ResponseData data, Operation operation = Operation::Preview) {
    return Response{.operation = operation,
                    .runtime = RuntimeSummary{"local path", "remote:"},
                    .data = std::move(data)};
}

template <typename Payload>
std::string present_out(const Payload& payload, int expected_code = 0) {
    return kasumi::test::capture_stdout([&] {
        EXPECT_EQ(kasumi::cli::present(payload), expected_code);
    });
}

std::string
present_out(const Response& value, bool full_paths, int expected_code = 0) {
    return kasumi::test::capture_stdout([&] {
        EXPECT_EQ(kasumi::cli::present(value, full_paths), expected_code);
    });
}

TEST(CliPresenterTest, PresentsEmptyAndPopulatedPlansWithTrafficAndRename) {
    const ScopedLanguage lang{Language::Portuguese};
    const auto empty_output = present_out(response(PlanReport{}));
    EXPECT_NE(empty_output.find("Nada a fazer"), std::string::npos);
    PlanReport report;
    report.has_conflicts = true;
    report.upload_bytes = 10;
    report.download_bytes = 20;
    report.items = {{PlanAction::RenameLocal, "old", "new", 0},
                    {PlanAction::Upload, "file", {}, 10},
                    {PlanAction::Download, "other", {}, 20},
                    {PlanAction::DeleteIgnoredLocalFile, "cache.bak", {}, 10}};
    const auto output = present_out(response(report));
    EXPECT_NE(output.find("modificações independentes"), std::string::npos);
    EXPECT_NE(output.find("old -> new"), std::string::npos);
    EXPECT_NE(output.find("Enviar"), std::string::npos);
    EXPECT_NE(output.find("Excluir arquivo ignorado descartável"),
              std::string::npos);
    EXPECT_NE(output.find("20 bytes"), std::string::npos);
    {
        const ScopedLanguage english{Language::English};
        const auto english_output = present_out(response(report));
        EXPECT_NE(english_output.find("Rename local file"), std::string::npos);
        EXPECT_NE(english_output.find("Delete disposable ignored file"),
                  std::string::npos);
        EXPECT_EQ(english_output.find("DeleteIgnoredLocalFile"),
                  std::string::npos);
    }
}

TEST(CliPresenterTest, FitsUtf8AndClosesInteractiveProgressBeforeErrors) {
    const ScopedLanguage lang{Language::English};
    EXPECT_EQ(kasumi::platform::fit_terminal_text("a界b", 3), "a界");
    EXPECT_EQ(kasumi::cli::format_eta(135), "2m 15s");
    EXPECT_EQ(kasumi::cli::format_eta(3840), "1h 04m");
    const auto output = kasumi::test::capture_stdout([] {
        kasumi::cli::ProgressDisplay display(
            {.interactive = true, .ansi = true, .fixed_width = 18});
        display.show({.activity = Activity::Downloading, .total_bytes = 100});
        display.show({.activity = Activity::Downloading,
                      .bytes = 100,
                      .total_bytes = 100});
        display.finish();
        kasumi::cli::print_error_line("failure");
    });
    EXPECT_NE(output.find("\r\x1b[2KDownloading"), std::string::npos);
    EXPECT_NE(output.find("\r\x1b[2K[ERROR] failure"), std::string::npos);
    const auto first_redraw = output.find('\r');
    ASSERT_NE(first_redraw, std::string::npos);
    EXPECT_LE(first_redraw, 17U);
}

TEST(CliPresenterTest, RedirectedProgressContainsOnlyPlainStageLines) {
    const ScopedLanguage lang{Language::English};
    const auto output = kasumi::test::capture_stdout([] {
        kasumi::cli::ProgressDisplay display(kasumi::platform::Terminal{});
        display.show({.activity = Activity::Downloading, .total_bytes = 100});
        display.show({.activity = Activity::Downloading,
                      .bytes = 100,
                      .total_bytes = 100});
        display.finish();
        kasumi::cli::print_error_line("failure");
    });
    EXPECT_EQ(output.find('\r'), std::string::npos);
    EXPECT_EQ(output.find("\x1b["), std::string::npos);
    EXPECT_EQ(output, "Downloading\n[ERROR] failure\n");
}

TEST(CliPresenterTest, LocalizesSingularAndPluralWireObjectCounts) {
    const auto completed =
        response(SyncCompleted{.wire_upload_bytes = 512,
                               .wire_download_bytes = 256,
                               .physical_objects_uploaded = 1,
                               .physical_objects_downloaded = 2},
                 Operation::Sync);
    {
        const ScopedLanguage english{Language::English};
        const auto output = present_out(completed);
        EXPECT_NE(output.find("(1 object)"), std::string::npos);
        EXPECT_NE(output.find("(2 objects)"), std::string::npos);
    }
    const ScopedLanguage portuguese{Language::Portuguese};
    const auto output = present_out(completed);
    EXPECT_NE(output.find("(1 objeto)"), std::string::npos);
    EXPECT_NE(output.find("(2 objetos)"), std::string::npos);
}

TEST(CliPresenterTest, DefaultSyncProgressAggregatesApplyingAndHidesZeroStage) {
    const ScopedLanguage lang{Language::English};
    const auto output = kasumi::test::capture_stdout([] {
        kasumi::cli::ProgressDisplay display(
            {.interactive = true, .ansi = true, .fixed_width = 120}, false);
        display.update(SyncProgress{.stage = SyncStage::Observing},
                       Operation::Sync);
        display.update(ActivityProgress{.activity = Activity::Scanning,
                                        .total_objects = 10,
                                        .stage_id = 1},
                       Operation::Sync);
        display.update(SyncProgress{.stage = SyncStage::Calculating},
                       Operation::Sync);
        display.update(SyncProgress{.stage = SyncStage::Applying},
                       Operation::Sync);
        display.update(ActivityProgress{.activity = Activity::Staging,
                                        .staged_bytes = 0,
                                        .stage_id = 2},
                       Operation::Sync);
        display.update(ActivityProgress{.activity = Activity::Uploading,
                                        .bytes = 100,
                                        .total_bytes = 100,
                                        .objects = 2,
                                        .total_objects = 2,
                                        .stage_id = 3},
                       Operation::Sync);
        display.update(ActivityProgress{.activity = Activity::Verifying,
                                        .objects = 2,
                                        .total_objects = 2,
                                        .stage_id = 4},
                       Operation::Sync);
        display.update(ActivityProgress{.activity = Activity::Uploading,
                                        .bytes = 200,
                                        .total_bytes = 200,
                                        .objects = 3,
                                        .total_objects = 3,
                                        .stage_id = 5},
                       Operation::Sync);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        display.update(SyncProgress{.stage = SyncStage::Publishing},
                       Operation::Sync);
        display.update(SyncProgress{.stage = SyncStage::Finalizing},
                       Operation::Sync);
    });
    EXPECT_EQ(output.find("0 bytes → 0 bytes"), std::string::npos);
    EXPECT_EQ(output.find("Scanning local files\n"), std::string::npos);
    EXPECT_NE(output.find("\r\x1b[2K[2/5]"), std::string::npos);
    EXPECT_NE(output.find("5/5 objects"), std::string::npos);
    EXPECT_NE(output.find("300 bytes/300 bytes"), std::string::npos);
    EXPECT_NE(output.find("Speed: avg "), std::string::npos);
    EXPECT_NE(output.find(" | min "), std::string::npos);
    EXPECT_NE(output.find(" | max "), std::string::npos);
    EXPECT_EQ(output.find("2/2 objects\n"), std::string::npos);
    EXPECT_EQ(output.find("Verifying | 2/2 objects\n"), std::string::npos);
}

TEST(CliPresenterTest, FullSyncProgressKeepsAllStagesAndPortugueseSpeed) {
    const ScopedLanguage lang{Language::Portuguese};
    const auto output = kasumi::test::capture_stdout([] {
        kasumi::cli::ProgressDisplay display(
            {.interactive = true, .ansi = true, .fixed_width = 120}, true);
        display.update(SyncProgress{.stage = SyncStage::Observing},
                       Operation::Sync);
        display.update(ActivityProgress{.activity = Activity::Scanning,
                                        .total_objects = 3,
                                        .cache_hits = 2,
                                        .files_hashed = 1,
                                        .stage_id = 1},
                       Operation::Sync);
        display.update(SyncProgress{.stage = SyncStage::Calculating},
                       Operation::Sync);
        display.update(SyncProgress{.stage = SyncStage::Applying},
                       Operation::Sync);
        display.update(ActivityProgress{.activity = Activity::Uploading,
                                        .bytes = 100,
                                        .total_bytes = 100,
                                        .objects = 2,
                                        .total_objects = 2,
                                        .stage_id = 2},
                       Operation::Sync);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        display.update(SyncProgress{.stage = SyncStage::Publishing},
                       Operation::Sync);
    });
    EXPECT_NE(output.find("Verificando arquivos locais"), std::string::npos);
    EXPECT_NE(output.find("2/2 objetos"), std::string::npos);
    EXPECT_NE(output.find("Velocidade: média "), std::string::npos);
    EXPECT_NE(output.find(" | mínima "), std::string::npos);
    EXPECT_NE(output.find(" | máxima "), std::string::npos);
}

TEST(CliPresenterTest, PresentsSuccessfulResponseVariants) {
    const ScopedLanguage lang{Language::Portuguese};
    const auto sync_output =
        present_out(response(SyncCompleted{}, Operation::Sync));
    EXPECT_NE(sync_output.find("[OK]"), std::string::npos);
    EXPECT_NE(sync_output.find("Sincronização concluída."), std::string::npos);
    EXPECT_EQ(sync_output.find("sem erros"), std::string::npos);
    EXPECT_EQ(sync_output.find("Local:"), std::string::npos);
    EXPECT_EQ(sync_output.find("Destino:"), std::string::npos);

    const auto fsck_output = present_out(response(
        FsckCompleted{.checked_objects = 1, .checked_plaintext_bytes = 6},
        Operation::Fsck));
    EXPECT_NE(fsck_output.find("1 objeto único auditado"), std::string::npos);
    EXPECT_NE(fsck_output.find("6 bytes"), std::string::npos);
    EXPECT_EQ(fsck_output.find("[Auditing destination integrity]"),
              std::string::npos);
    EXPECT_EQ(kasumi::cli::present(
                  response(GarbageCollectCompleted{.candidate_objects = 3},
                           Operation::GarbageCollect)),
              0);
}

TEST(CliPresenterTest, RejectsCompletionPayloadForDifferentOperation) {
    const ScopedLanguage lang{Language::Portuguese};
    const auto output =
        present_out(response(SyncCompleted{}, Operation::GarbageCollect), 1);
    EXPECT_EQ(output.find("Sincronização concluída."), std::string::npos);
    EXPECT_EQ(output.find("[OK]"), std::string::npos);
}

TEST(CliPresenterTest, PartialSyncIsLocalizedAndReturnsDistinctExitCode) {
    SyncCompleted partial{
        .pending = 1, .pending_paths = {"docs/missing.txt"}, .partial = true};
    const ScopedLanguage english{Language::English};
    const auto english_output =
        present_out(response(partial, Operation::Sync), 2);
    EXPECT_NE(english_output.find("Synchronization completed partially"),
              std::string::npos);
    EXPECT_NE(english_output.find("1 file is waiting"), std::string::npos);
    EXPECT_NE(english_output.find("docs/missing.txt"), std::string::npos);
    EXPECT_EQ(english_output.find("[OK]"), std::string::npos);
    EXPECT_EQ(english_output.find("Everything in sync"), std::string::npos);

    kasumi::cli::i18n::set_language(Language::Portuguese);
    const auto portuguese_output =
        present_out(response(partial, Operation::Sync), 2);
    EXPECT_NE(portuguese_output.find("concluída parcialmente"),
              std::string::npos);
    EXPECT_NE(portuguese_output.find("1 arquivo aguarda"), std::string::npos);
    EXPECT_NE(portuguese_output.find("Pendentes:"), std::string::npos);
}

TEST(CliPresenterTest, PresentsStructuralInventoryAuditAndExitStatus) {
    const ScopedLanguage english{Language::English};
    auto audited = response(SyncCompleted{}, Operation::Sync);
    audited.inventory_audit = InventoryAuditReport{
        .referenced_content = 4,
        .present_content = 2,
        .missing_content = 1,
        .orphan_content = 1,
        .unknown_objects = 0,
    };
    const auto english_output = present_out(audited, 2);
    EXPECT_NE(english_output.find("Structural inventory audit"),
              std::string::npos);
    EXPECT_NE(english_output.find("Referenced content: 4"), std::string::npos);
    EXPECT_NE(english_output.find("Missing: 1"), std::string::npos);

    kasumi::cli::i18n::set_language(Language::Portuguese);
    audited.inventory_audit = InventoryAuditReport{
        .referenced_content = 1,
        .present_content = 1,
    };
    const auto portuguese_output = present_out(audited);
    EXPECT_NE(portuguese_output.find("Auditoria estrutural"),
              std::string::npos);
    EXPECT_NE(portuguese_output.find("Conteúdo referenciado: 1"),
              std::string::npos);
}

TEST(CliPresenterTest, AuditFailureStatesSyncCompletionAndPublication) {
    const ScopedLanguage english{Language::English};
    const Error error{
        .operation = Operation::Sync,
        .code = ErrorCode::InventoryAuditFailure,
        .detail = "remote inventory changed",
        .sync_completed =
            SyncCompleted{.published = true, .pending = 2, .partial = true},
    };
    const auto output = present_out(error, 1);
    EXPECT_NE(output.find("Inventory audit failed"), std::string::npos);
    EXPECT_NE(output.find("Synchronization completed before"),
              std::string::npos);
    EXPECT_NE(output.find("published changes remain remote"),
              std::string::npos);
    EXPECT_NE(output.find("Synchronization completed partially"),
              std::string::npos);
    EXPECT_NE(output.find("2 files are waiting"), std::string::npos);
}

TEST(CliPresenterTest, PendingPathsAreBoundedUnlessFullIsRequested) {
    PlanReport report;
    for (int index = 0; index < 12; ++index) {
        report.pending_paths.emplace_back(std::string{"pending-"} +
                                          static_cast<char>('a' + index));
    }
    const ScopedLanguage lang{Language::English};
    const auto bounded = present_out(response(report), 2);
    EXPECT_NE(bounded.find("pending-a"), std::string::npos);
    EXPECT_NE(bounded.find("pending-e"), std::string::npos);
    EXPECT_EQ(bounded.find("pending-f"), std::string::npos);
    EXPECT_NE(bounded.find("pending-h"), std::string::npos);
    EXPECT_NE(bounded.find("pending-l"), std::string::npos);
    EXPECT_NE(bounded.find("2 paths omitted"), std::string::npos);
    EXPECT_EQ(bounded.find("Nothing to do"), std::string::npos);

    const auto complete = present_out(response(report), true, 2);
    EXPECT_NE(complete.find("pending-f"), std::string::npos);
    EXPECT_EQ(complete.find("paths omitted"), std::string::npos);
}

TEST(CliPresenterTest, PresentsPluralFsckSummaryAndOmitsUnknownBytes) {
    const ScopedLanguage lang{Language::English};
    const auto output = present_out(
        response(FsckCompleted{.checked_objects = 2}, Operation::Fsck));
    EXPECT_NE(output.find("2 unique objects audited."), std::string::npos);
    EXPECT_EQ(output.find("Expected plaintext:"), std::string::npos);
}

TEST(CliPresenterTest, PresentsSynchronizationErrorsWithoutSecrets) {
    const ScopedLanguage lang{Language::Portuguese};
    const Error error{.operation = Operation::Sync,
                      .code = ErrorCode::SynchronizationFailure,
                      .detail = "falha controlada",
                      .runtime = std::nullopt};
    const auto output = present_out(error, 1);
    EXPECT_NE(output.find("falha controlada"), std::string::npos);
}

TEST(CliPresenterTest, PresentsRemoteHeadsSemantically) {
    const ScopedLanguage lang{Language::Portuguese};
    using namespace kasumi::application;
    const RemoteHeadInfo first{.commit_id = "commit-a",
                               .height = 9,
                               .created_at = 100,
                               .parent_ids = {"parent-a"},
                               .root_hash = "root-a",
                               .file_count = 3,
                               .directory_count = 2,
                               .total_bytes = 6};
    const RemoteHeadInfo second{.commit_id = "commit-b",
                                .height = 9,
                                .created_at = 200,
                                .root_hash = "root-b"};

    const auto empty = present_out(InspectionResponse{});
    EXPECT_EQ(empty, "Nenhuma head remota publicada.\n");
    EXPECT_TRUE(std::holds_alternative<RemoteHeadsReport>(
        InspectionResponse{}.payload));

    InspectionResponse response{
        .payload = RemoteHeadsReport{.history_present = true,
                                     .observed_height = 9,
                                     .heads = {first, second}}};
    const auto output = present_out(response);
    EXPECT_NE(output.find("Heads remotas (2)"), std::string::npos);
    EXPECT_NE(output.find("Commit: commit-a"), std::string::npos);
    EXPECT_NE(output.find("Commit: commit-b"), std::string::npos);
    EXPECT_NE(output.find("Altura: 9"), std::string::npos);
    EXPECT_NE(output.find("Pais: 1"), std::string::npos);
    EXPECT_NE(output.find("Arquivos: 3"), std::string::npos);
    EXPECT_NE(output.find("Diretórios: 2"), std::string::npos);
    EXPECT_NE(output.find("Tamanho: 6 bytes"), std::string::npos);
    EXPECT_NE(output.find("Raiz: root-a"), std::string::npos);
    EXPECT_LT(output.find("Commit: commit-a"), output.find("Commit: commit-b"));
}

TEST(CliPresenterTest, PresentsRemoteTreeSemantically) {
    const ScopedLanguage lang{Language::Portuguese};
    const RemoteTreeReport report{
        .history_present = true,
        .commit_id = "commit-tree",
        .height = 14,
        .created_at = 123,
        .root_hash = "root",
        .total_bytes = 6,
        .file_count = 2,
        .directory_count = 2,
        .entries = {
            RemoteTreeEntry{.path = "docs",
                            .type = RemoteTreeEntryType::Directory},
            RemoteTreeEntry{
                .path = "docs/a.txt", .logical_hash = "hash-a", .size = 1},
            RemoteTreeEntry{.path = "docs/nested",
                            .type = RemoteTreeEntryType::Directory},
            RemoteTreeEntry{.path = "docs/nested/b.txt",
                            .logical_hash = "hash-b",
                            .size = 2},
        }};
    const InspectionResponse response{
        .operation = InspectionOperation::RemoteTree, .payload = report};

    const auto output = present_out(response);
    EXPECT_NE(output.find("Head: commit-tree"), std::string::npos);
    EXPECT_NE(output.find("Altura: 14"), std::string::npos);
    EXPECT_NE(output.find("Arquivos: 2"), std::string::npos);
    EXPECT_NE(output.find("Diretórios: 2"), std::string::npos);
    EXPECT_NE(output.find("Tamanho: 6 bytes"), std::string::npos);
    EXPECT_NE(output.find("\n/\n"), std::string::npos);
    EXPECT_NE(output.find("  docs/"), std::string::npos);
    EXPECT_NE(output.find("    a.txt  1 bytes"), std::string::npos);
    EXPECT_NE(output.find("    nested/"), std::string::npos);
    EXPECT_NE(output.find("      b.txt  2 bytes"), std::string::npos);
    EXPECT_EQ(output.find("hash-a"), std::string::npos);
    EXPECT_LT(output.find("  docs/"), output.find("    a.txt"));
    EXPECT_LT(output.find("    nested/"), output.find("      b.txt"));
}

TEST(CliPresenterTest, PresentsRemoteCommitsWithoutInternalDetails) {
    const ScopedLanguage lang{Language::Portuguese};
    const InspectionResponse empty{.operation =
                                       InspectionOperation::RemoteCommits,
                                   .payload = RemoteCommitsReport{}};
    const auto empty_output = present_out(empty);
    EXPECT_EQ(empty_output, "Nenhum commit remoto publicado.\n");

    const InspectionResponse response{
        .operation = InspectionOperation::RemoteCommits,
        .payload = RemoteCommitsReport{
            .history_present = true,
            .observed_height = 3,
            .logical_head_ids = {"commit-head"},
            .commits = {
                RemoteCommitInfo{.commit_id = "commit-head",
                                 .height = 3,
                                 .created_at = 300,
                                 .parent_ids = {"parent-a", "parent-b"},
                                 .logical_head = true,
                                 .root_hash = "root-secret",
                                 .total_bytes = 42,
                                 .entry_count = 5},
                RemoteCommitInfo{.commit_id = "commit-ancestor",
                                 .height = 2,
                                 .created_at = 200,
                                 .ancestral_marked = true},
                RemoteCommitInfo{
                    .commit_id = "commit-old", .height = 1, .created_at = 100},
            }}};

    const auto output = present_out(response);
    EXPECT_NE(output.find("Commits remotos (3)"), std::string::npos);
    EXPECT_NE(output.find("HEAD"), std::string::npos);
    EXPECT_NE(output.find("MARKER ANCESTRAL"), std::string::npos);
    EXPECT_NE(output.find("ANCESTRAL"), std::string::npos);
    EXPECT_NE(output.find("Pais: 2"), std::string::npos);
    EXPECT_NE(output.find("Entradas: 5"), std::string::npos);
    EXPECT_NE(output.find("Tamanho: 42 bytes"), std::string::npos);
    EXPECT_EQ(output.find("root-secret"), std::string::npos);
    EXPECT_EQ(output.find("parent-a"), std::string::npos);
    EXPECT_EQ(output.find("parent-b"), std::string::npos);
}

TEST(CliPresenterTest, PresentsRemoteTreeSelectionErrorsWithCandidates) {
    const ScopedLanguage lang{Language::Portuguese};
    const InspectionError multiple{
        .operation = InspectionOperation::RemoteTree,
        .code = InspectionErrorCode::HeadSelectionRequired,
        .detail = "Remote history has multiple logical heads.",
        .candidate_ids = {"head-a", "head-b"}};
    const auto multiple_output = present_out(multiple, 1);
    EXPECT_NE(multiple_output.find("multiple logical heads"),
              std::string::npos);
    EXPECT_NE(multiple_output.find("head-a"), std::string::npos);
    EXPECT_NE(multiple_output.find("head-b"), std::string::npos);
    EXPECT_NE(multiple_output.find("--head"), std::string::npos);

    const InspectionError missing{
        .operation = InspectionOperation::RemoteTree,
        .code = InspectionErrorCode::RemoteHeadNotFound,
        .detail = "requested head is not among current logical heads",
        .candidate_ids = {"head-a"}};
    const auto missing_output = present_out(missing, 1);
    EXPECT_NE(missing_output.find(
                  "requested head is not among current logical heads"),
              std::string::npos);
    EXPECT_NE(missing_output.find("head-a"), std::string::npos);
}

TEST(CliPresenterTest, RejectsIncoherentInspectionPayloadWithoutThrowing) {
    const ScopedLanguage lang{Language::Portuguese};
    const InspectionResponse response{.operation =
                                          InspectionOperation::RemoteTree,
                                      .payload = RemoteHeadsReport{}};
    const auto output = present_out(response, 1);
    EXPECT_NE(output.find("resposta de inspeção inconsistente"),
              std::string::npos);
}

TEST(CliPresenterTest, PresentsRemoteSummarySemantically) {
    const ScopedLanguage lang{Language::Portuguese};
    const InspectionResponse response{
        .operation = InspectionOperation::RemoteSummary,
        .payload = RemoteSummaryReport{.history_present = true,
                                       .observed_height = 6,
                                       .reachable_commit_count = 5,
                                       .logical_head_count = 2,
                                       .has_conflicts = true,
                                       .missing_content_count = 1,
                                       .orphan_content_count = 3,
                                       .active_writer_count = 1}};
    const auto output = present_out(response);
    EXPECT_NE(output.find("Resumo remoto"), std::string::npos);
    EXPECT_NE(output.find("Histórico: presente"), std::string::npos);
    EXPECT_NE(output.find("Altura: 6"), std::string::npos);
    EXPECT_NE(output.find("Commits alcançáveis: 5"), std::string::npos);
    EXPECT_NE(output.find("Heads lógicas: 2"), std::string::npos);
    EXPECT_NE(output.find("Conflitos: sim"), std::string::npos);
    EXPECT_NE(output.find("Conteúdos ausentes: 1"), std::string::npos);
    EXPECT_NE(output.find("Conteúdos órfãos: 3"), std::string::npos);
    EXPECT_NE(output.find("Writers ativos: 1"), std::string::npos);
    EXPECT_EQ(output.find("[Rede]"), std::string::npos);
}

TEST(CliPresenterTest, PresentsRemoteStatSemantically) {
    const ScopedLanguage lang{Language::Portuguese};
    const InspectionResponse response{.operation =
                                          InspectionOperation::RemoteStat,
                                      .payload = RemoteStatReport{
                                          .observed_height = 4,
                                          .has_conflicts = false,
                                          .path = "docs/relatório final.pdf",
                                          .type = RemoteTreeEntryType::File,
                                          .logical_hash = "logical-hash",
                                          .size = 42,
                                          .modified_at_unix_nanoseconds = 123,
                                      }};
    const auto output = present_out(response);
    EXPECT_NE(output.find("Propriedades remotas"), std::string::npos);
    EXPECT_NE(output.find("árvore lógica efetiva"), std::string::npos);
    EXPECT_NE(output.find("Caminho: docs/relatório final.pdf"),
              std::string::npos);
    EXPECT_NE(output.find("Tipo: arquivo"), std::string::npos);
    EXPECT_NE(output.find("Hash lógico: logical-hash"), std::string::npos);
    EXPECT_NE(output.find("Tamanho: 42 bytes"), std::string::npos);
    EXPECT_NE(output.find("Modificado em (ns Unix): 123"), std::string::npos);
}

TEST(CliPresenterTest, PresentsRemoteCommitParentsAndVariants) {
    const ScopedLanguage lang{Language::Portuguese};
    const InspectionResponse response{
        .operation = InspectionOperation::RemoteCommit,
        .payload = RemoteCommitReport{
            .commit = RemoteCommitInfo{.commit_id = "commit",
                                       .height = 3,
                                       .created_at = 200,
                                       .parent_ids = {"parent-a", "parent-b"},
                                       .logical_head = true,
                                       .physically_marked = true,
                                       .root_hash = "root",
                                       .total_bytes = 42,
                                       .entry_count = 2},
            .variants = {
                RemoteCommitVariantInfo{
                    .ciphertext_id = "a",
                    .object_identifier = "history/commits/commit/a",
                    .state = RemoteCommitVariantState::Valid},
                RemoteCommitVariantInfo{
                    .ciphertext_id = "b",
                    .object_identifier = "history/commits/commit/b",
                    .state = RemoteCommitVariantState::InvalidCiphertext},
                RemoteCommitVariantInfo{
                    .ciphertext_id = "c",
                    .object_identifier = "history/commits/commit/c",
                    .state = RemoteCommitVariantState::InvalidCommit},
            }}};
    const auto output = present_out(response);
    EXPECT_NE(output.find("Commit remoto"), std::string::npos);
    EXPECT_NE(output.find("Pais (2)"), std::string::npos);
    EXPECT_NE(output.find("parent-a"), std::string::npos);
    EXPECT_NE(output.find("parent-b"), std::string::npos);
    EXPECT_NE(output.find("Variantes físicas (3)"), std::string::npos);
    EXPECT_NE(output.find("Estado: válida"), std::string::npos);
    EXPECT_NE(output.find("Estado: ciphertext inválido"), std::string::npos);
    EXPECT_NE(output.find("Estado: commit inválido"), std::string::npos);
    EXPECT_LT(output.find("Ciphertext: a"), output.find("Ciphertext: b"));
}

TEST(CliPresenterTest, PresentsAuthenticatedRemoteFileDownload) {
    const ScopedLanguage lang{Language::Portuguese};
    const InspectionResponse response{
        .operation = InspectionOperation::RemoteGet,
        .payload =
            RemoteFileReport{.path = "docs/relatório.pdf",
                             .destination_path = "download/relatório.pdf",
                             .logical_hash = "logical-hash",
                             .content_id = "content-id",
                             .size = 42}};
    const auto output = present_out(response);
    EXPECT_NE(output.find("Arquivo remoto salvo"), std::string::npos);
    EXPECT_NE(output.find("Caminho: docs/relatório.pdf"), std::string::npos);
    EXPECT_NE(output.find("Destino: download/relatório.pdf"),
              std::string::npos);
    EXPECT_NE(output.find("Hash lógico: logical-hash"), std::string::npos);
    EXPECT_NE(output.find("Tamanho: 42 bytes"), std::string::npos);
    EXPECT_EQ(output.find("content-id"), std::string::npos);
    EXPECT_EQ(output.find("[Rede]"), std::string::npos);
}

TEST(CliPresenterTest, PresentsAuthenticatedEpochChainAndLinks) {
    const ScopedLanguage lang{Language::Portuguese};
    RemoteEpochInfo epoch{
        .vault_id = "vault-id",
        .sequence = 1,
        .epoch_id = "epoch-id",
        .issued_at = 123,
        .min_history_depth = 5,
        .min_history_age_hours = 6,
        .anchors = {{.commit_id = "commit-id", .height = 9}},
        .previous_epoch_id = "previous-id",
        .next_epoch_id = "next-id",
    };
    const auto list_output = present_out(
        InspectionResponse{.operation = InspectionOperation::RemoteEpochs,
                           .payload = RemoteEpochsReport{.epochs = {epoch}}});
    EXPECT_NE(list_output.find("Epochs remotos: 1"), std::string::npos);
    EXPECT_NE(list_output.find("Vault ID: vault-id"), std::string::npos);
    EXPECT_NE(list_output.find("Retenção mínima: 5 commit(s), 6 hora(s)"),
              std::string::npos);
    EXPECT_NE(list_output.find("commit-id (altura 9)"), std::string::npos);
    EXPECT_NE(list_output.find("Epoch anterior: previous-id"),
              std::string::npos);
    EXPECT_NE(list_output.find("Próximo Epoch: next-id"), std::string::npos);

    const auto epoch_output = present_out(InspectionResponse{
        .operation = InspectionOperation::RemoteEpoch,
        .payload = RemoteEpochReport{.epoch = std::move(epoch)}});
    EXPECT_NE(epoch_output.find("Epoch remoto"), std::string::npos);
}

TEST(CliPresenterTest, PresentsContentInventoryAuditAndDetail) {
    const ScopedLanguage lang{Language::Portuguese};
    RemoteContentInfo content{
        .content_id = "content-id",
        .logical_hash = "logical-hash",
        .size = 42,
        .paths = {"docs/a.txt"},
        .referenced = true,
        .physically_present = true,
        .current_tree = true,
        .state = RemoteContentState::Valid,
    };
    const auto audit_output = present_out(InspectionResponse{
        .operation = InspectionOperation::RemoteContentsAudit,
        .payload = RemoteContentsReport{.audited = true,
                                        .referenced_count = 1,
                                        .physical_count = 1,
                                        .valid_count = 1,
                                        .contents = {content}}});
    EXPECT_NE(audit_output.find("auditoria profunda"), std::string::npos);
    EXPECT_NE(audit_output.find("Válidos: 1"), std::string::npos);
    EXPECT_NE(audit_output.find("Estado: válido"), std::string::npos);
    EXPECT_NE(audit_output.find("docs/a.txt"), std::string::npos);

    const auto detail_output = present_out(InspectionResponse{
        .operation = InspectionOperation::RemoteContent,
        .payload = RemoteContentReport{.content = std::move(content)}});
    EXPECT_NE(detail_output.find("Conteúdo remoto"), std::string::npos);
    EXPECT_NE(detail_output.find("Content ID: content-id"), std::string::npos);
}

TEST(CliPresenterTest, PresentsEveryPhysicalInspectionReportInPortuguese) {
    const ScopedLanguage lang{Language::Portuguese};
    const auto present_and_capture = [](const InspectionResponse& response) {
        const auto output = present_out(response);
        EXPECT_EQ(output.find("[Rede]"), std::string::npos);
        return output;
    };

    const auto markers = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteMarkers,
        .payload = RemoteMarkersReport{
            .logical_count = 1,
            .ancestral_count = 1,
            .invalid_count = 1,
            .markers = {{.object_identifier = "head-atual",
                         .commit_id = "commit-atual",
                         .ciphertext_id = "variante-atual",
                         .state = RemoteMarkerState::LogicalHead},
                        {.object_identifier = "head-antiga",
                         .state = RemoteMarkerState::Ancestral},
                        {.object_identifier = "head-ruim",
                         .state = RemoteMarkerState::InvalidMarker}}}});
    EXPECT_NE(markers.find("head lógica autenticada"), std::string::npos);
    EXPECT_NE(markers.find("marker ancestral autenticado"), std::string::npos);
    EXPECT_NE(markers.find("marker inválido"), std::string::npos);

    const auto objects = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteObjects,
        .payload = RemoteObjectsReport{
            .unknown_count = 1,
            .objects = {{.identifier = "objeto-x",
                         .category = RemoteObjectCategory::Unknown,
                         .relation = "not audited"}}}});
    EXPECT_NE(objects.find("Namespace físico remoto"), std::string::npos);
    EXPECT_NE(objects.find("desconhecido"), std::string::npos);
    EXPECT_NE(objects.find("not audited"), std::string::npos);

    const auto orphans = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteOrphans,
        .payload = RemoteOrphansReport{
            .objects = {{.identifier = "commit-órfão",
                         .kind = RemoteOrphanKind::Commit,
                         .removal_candidate = true},
                        {.identifier = "epoch-protegido",
                         .kind = RemoteOrphanKind::ProtectedEpoch}}}});
    EXPECT_NE(orphans.find("commit lógico órfão"), std::string::npos);
    EXPECT_NE(orphans.find("Epoch histórico protegido"), std::string::npos);
    EXPECT_NE(orphans.find("não é um plano de GC"), std::string::npos);

    const auto writers = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteWriters,
        .payload = RemoteWritersReport{
            .barrier_present = true,
            .maintenance_blocked = true,
            .writers = {{.identifier = "writer",
                         .state = RemoteWriterState::Indeterminate}}}});
    EXPECT_NE(writers.find("Barrier: presente"), std::string::npos);
    EXPECT_NE(writers.find("indeterminado"), std::string::npos);

    const auto health = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteHealth,
        .payload =
            RemoteHealthReport{.state = RemoteHealthState::Critical,
                               .missing_content_count = 1,
                               .reasons = {"conteúdo alcançável ausente"}}});
    EXPECT_NE(health.find("Saúde remota: crítico"), std::string::npos);
    EXPECT_NE(health.find("Conteúdos ausentes: 1"), std::string::npos);
}

TEST(CliPresenterTest, PresentsEveryPhysicalInspectionReportInEnglish) {
    const ScopedLanguage lang{Language::English};
    const auto present_and_capture = [](const InspectionResponse& response) {
        const auto output = present_out(response);
        EXPECT_EQ(output.find("[Rede]"), std::string::npos);
        return output;
    };

    const auto markers = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteMarkers,
        .payload = RemoteMarkersReport{
            .logical_count = 1,
            .ancestral_count = 1,
            .invalid_count = 1,
            .markers = {{.object_identifier = "head-atual",
                         .commit_id = "commit-atual",
                         .ciphertext_id = "variante-atual",
                         .state = RemoteMarkerState::LogicalHead},
                        {.object_identifier = "head-antiga",
                         .state = RemoteMarkerState::Ancestral},
                        {.object_identifier = "head-ruim",
                         .state = RemoteMarkerState::InvalidMarker}}}});
    EXPECT_NE(markers.find("authenticated logical head"), std::string::npos);
    EXPECT_NE(markers.find("authenticated ancestral marker"),
              std::string::npos);
    EXPECT_NE(markers.find("invalid marker"), std::string::npos);

    const auto objects = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteObjects,
        .payload = RemoteObjectsReport{
            .unknown_count = 1,
            .objects = {{.identifier = "object-x",
                         .category = RemoteObjectCategory::Unknown,
                         .relation = "not audited"}}}});
    EXPECT_NE(objects.find("Remote physical namespace"), std::string::npos);
    EXPECT_NE(objects.find("unknown"), std::string::npos);
    EXPECT_NE(objects.find("not audited"), std::string::npos);

    const auto orphans = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteOrphans,
        .payload = RemoteOrphansReport{
            .objects = {{.identifier = "orphan-commit",
                         .kind = RemoteOrphanKind::Commit,
                         .removal_candidate = true},
                        {.identifier = "protected-epoch",
                         .kind = RemoteOrphanKind::ProtectedEpoch}}}});
    EXPECT_NE(orphans.find("orphan logical commit"), std::string::npos);
    EXPECT_NE(orphans.find("protected historical Epoch"), std::string::npos);
    EXPECT_NE(orphans.find("not a GC plan"), std::string::npos);

    const auto writers = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteWriters,
        .payload = RemoteWritersReport{
            .barrier_present = true,
            .maintenance_blocked = true,
            .writers = {{.identifier = "writer",
                         .state = RemoteWriterState::Indeterminate}}}});
    EXPECT_NE(writers.find("Barrier: present"), std::string::npos);
    EXPECT_NE(writers.find("indeterminate"), std::string::npos);

    const auto health = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteHealth,
        .payload =
            RemoteHealthReport{.state = RemoteHealthState::Critical,
                               .missing_content_count = 1,
                               .reasons = {"missing reachable content"}}});
    EXPECT_NE(health.find("Remote health: critical"), std::string::npos);
    EXPECT_NE(health.find("Missing contents: 1"), std::string::npos);
}

TEST(CliPresenterTest, PresentsRemoteLookupErrors) {
    const ScopedLanguage lang{Language::Portuguese};
    for (const auto code : {InspectionErrorCode::RemotePathNotFound,
                            InspectionErrorCode::RemoteCommitNotFound,
                            InspectionErrorCode::RemotePathIsDirectory,
                            InspectionErrorCode::RemoteContentNotFound,
                            InspectionErrorCode::RemoteContentInvalid,
                            InspectionErrorCode::DestinationFailure,
                            InspectionErrorCode::RemoteEpochNotFound}) {
        const auto error_output = present_out(
            InspectionError{.operation = InspectionOperation::RemoteStat,
                            .code = code,
                            .detail = "not found"},
            1);
        EXPECT_NE(error_output.find("not found"), std::string::npos);
    }
}

TEST(CliPresenterTest, PresentsOutputsInEnglishWhenConfigured) {
    const ScopedLanguage lang{Language::English};

    const auto empty_output = present_out(response(PlanReport{}));
    EXPECT_NE(empty_output.find("Nothing to do"), std::string::npos);

    const auto sync_output =
        present_out(response(SyncCompleted{}, Operation::Sync));
    EXPECT_NE(sync_output.find("Synchronization completed."),
              std::string::npos);

    const auto heads_empty = present_out(InspectionResponse{});
    EXPECT_NE(heads_empty.find("No remote heads published."),
              std::string::npos);
}

TEST(CliPresenterTest, PresentsSyncProgressStagesAndSummaryInPortuguese) {
    const ScopedLanguage lang{Language::Portuguese};

    const auto output = kasumi::test::capture_stdout([&] {
        kasumi::cli::present(SyncProgress{.stage = SyncStage::Observing});
        kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating});
        SyncCompleted summary{
            .total = 137,
            .uploaded = 92,
            .downloaded = 31,
            .removed = 14,
            .renamed = 0,
            .created_dirs = 0,
            .removed_dirs = 0,
            .published = true,
        };
        kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating,
                                          .summary = summary,
                                          .total_items = 137});
        kasumi::cli::present(
            SyncProgress{.stage = SyncStage::Applying, .total_items = 137});
        kasumi::cli::present(SyncProgress{.stage = SyncStage::Publishing});
        kasumi::cli::present(SyncProgress{.stage = SyncStage::Finalizing});
        EXPECT_EQ(kasumi::cli::present(response(summary, Operation::Sync)), 0);
    });
    EXPECT_NE(output.find("[1/5] Observando estado local e remoto..."),
              std::string::npos);
    EXPECT_NE(output.find("[2/5] Calculando alterações..."), std::string::npos);
    EXPECT_NE(output.find("137 alterações | ↑ 92 | ↓ 31 | - 14"),
              std::string::npos);
    EXPECT_NE(output.find("[3/5] Aplicando alterações..."), std::string::npos);
    EXPECT_NE(output.find("[4/5] Publicando novo estado..."),
              std::string::npos);
    EXPECT_NE(output.find("[5/5] Finalizando..."), std::string::npos);
    EXPECT_NE(output.find("[OK]"), std::string::npos);
    EXPECT_NE(output.find("Sincronização concluída."), std::string::npos);

    // Verify individual paths and internal transitions are not exposed
    EXPECT_EQ(output.find("CommitPrepared"), std::string::npos);
    EXPECT_EQ(output.find("HeadPublished"), std::string::npos);
    EXPECT_EQ(output.find("a.txt"), std::string::npos);
}

TEST(CliPresenterTest, PresentsSyncProgressStagesAndSummaryInEnglish) {
    const ScopedLanguage lang{Language::English};

    const auto output = kasumi::test::capture_stdout([&] {
        kasumi::cli::present(SyncProgress{.stage = SyncStage::Observing});
        kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating});
        SyncCompleted summary{
            .total = 5,
            .uploaded = 2,
            .downloaded = 1,
            .removed = 1,
            .renamed = 1,
            .created_dirs = 0,
            .removed_dirs = 0,
            .published = false,
        };
        kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating,
                                          .summary = summary,
                                          .total_items = 5});
        kasumi::cli::present(
            SyncProgress{.stage = SyncStage::Applying, .total_items = 5});
        // Stage 4 (Publishing) omitted when publication is not required
        kasumi::cli::present(SyncProgress{.stage = SyncStage::Finalizing});
        EXPECT_EQ(kasumi::cli::present(response(summary, Operation::Sync)), 0);
    });
    EXPECT_NE(output.find("[1/5] Observing local and remote state..."),
              std::string::npos);
    EXPECT_NE(output.find("[2/5] Calculating changes..."), std::string::npos);
    EXPECT_NE(output.find("5 changes | ↑ 2 | ↓ 1 | - 1 | → 1"),
              std::string::npos);
    EXPECT_NE(output.find("[3/5] Applying changes..."), std::string::npos);
    EXPECT_EQ(output.find("[4/5]"), std::string::npos);
    EXPECT_NE(output.find("[5/5] Finalizing..."), std::string::npos);
    EXPECT_NE(output.find("[OK]"), std::string::npos);
    EXPECT_NE(output.find("Synchronization completed."), std::string::npos);
}

TEST(CliPresenterTest, PresentsSyncProgressNoChangesInPortugueseAndEnglish) {
    kasumi::cli::i18n::set_language(Language::Portuguese);
    {
        const auto output = kasumi::test::capture_stdout([&] {
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Observing});
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating});
            SyncCompleted empty_summary{};
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating,
                                              .summary = empty_summary});
            EXPECT_EQ(
                kasumi::cli::present(response(empty_summary, Operation::Sync)),
                0);
        });
        EXPECT_NE(output.find("[1/5] Observando estado local e remoto..."),
                  std::string::npos);
        EXPECT_NE(output.find("[2/5] Calculando alterações..."),
                  std::string::npos);
        EXPECT_NE(output.find("Tudo sincronizado."), std::string::npos);
        EXPECT_EQ(output.find("[3/5]"), std::string::npos);
        EXPECT_EQ(output.find("[4/5]"), std::string::npos);
        EXPECT_EQ(output.find("[5/5]"), std::string::npos);
        EXPECT_NE(output.find("[OK]"), std::string::npos);
        EXPECT_NE(output.find("Sincronização concluída."), std::string::npos);
    }

    kasumi::cli::i18n::set_language(Language::English);
    {
        const auto output = kasumi::test::capture_stdout([&] {
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Observing});
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating});
            SyncCompleted empty_summary{};
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating,
                                              .summary = empty_summary});
            EXPECT_EQ(
                kasumi::cli::present(response(empty_summary, Operation::Sync)),
                0);
        });
        EXPECT_NE(output.find("[1/5] Observing local and remote state..."),
                  std::string::npos);
        EXPECT_NE(output.find("[2/5] Calculating changes..."),
                  std::string::npos);
        EXPECT_NE(output.find("Everything in sync."), std::string::npos);
        EXPECT_EQ(output.find("[3/5]"), std::string::npos);
        EXPECT_EQ(output.find("[4/5]"), std::string::npos);
        EXPECT_EQ(output.find("[5/5]"), std::string::npos);
        EXPECT_NE(output.find("[OK]"), std::string::npos);
        EXPECT_NE(output.find("Synchronization completed."), std::string::npos);
    }
}

TEST(CliPresenterTest, PresentsDirectoriesAndSingularPluralCorrectly) {
    kasumi::cli::i18n::set_language(Language::Portuguese);
    {
        const auto output = kasumi::test::capture_stdout([&] {
            SyncCompleted summary{
                .total = 4,
                .uploaded = 1,
                .downloaded = 0,
                .removed = 1,
                .renamed = 0,
                .created_dirs = 1,
                .removed_dirs = 1,
                .published = false,
            };
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating,
                                              .summary = summary,
                                              .total_items = 4});
        });
        EXPECT_NE(output.find("4 alterações | ↑ 1 | - 1 | + 1 dir | - 1 dir"),
                  std::string::npos);
    }

    {
        const auto output = kasumi::test::capture_stdout([&] {
            SyncCompleted single{
                .total = 1,
                .uploaded = 1,
            };
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating,
                                              .summary = single,
                                              .total_items = 1});
        });
        EXPECT_NE(output.find("1 alteração | ↑ 1"), std::string::npos);
    }

    kasumi::cli::i18n::set_language(Language::English);
    {
        const auto output = kasumi::test::capture_stdout([&] {
            SyncCompleted multiple_dirs{
                .total = 4,
                .created_dirs = 2,
                .removed_dirs = 2,
            };
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating,
                                              .summary = multiple_dirs,
                                              .total_items = 4});
        });
        EXPECT_NE(output.find("4 changes | + 2 dirs | - 2 dirs"),
                  std::string::npos);
    }
}

TEST(CliPresenterTest, FormatsSizesAccuratelyAndConsistently) {
    using kasumi::cli::format_size;
    EXPECT_EQ(format_size(0), "0 bytes");
    EXPECT_EQ(format_size(1), "1 bytes");
    EXPECT_EQ(format_size(842), "842 bytes");
    EXPECT_EQ(format_size(1023), "1023 bytes");
    EXPECT_EQ(format_size(1024), "1 KB");
    EXPECT_EQ(format_size(1536), "1.5 KB");
    EXPECT_EQ(format_size(12698), "12.4 KB");
    EXPECT_EQ(format_size(1572864), "1.5 MB");
    EXPECT_EQ(format_size(33239859), "31.7 MB");
    EXPECT_EQ(format_size(297795584), "284 MB");
    EXPECT_EQ(format_size(1503238553), "1.4 GB");
    EXPECT_EQ(format_size(1524713390), "1.42 GB");
}

TEST(CliPresenterTest, FormatsDurationsAsSecondsWithThreeDecimals) {
    using kasumi::cli::format_duration;
    EXPECT_EQ(format_duration(std::chrono::milliseconds(-1)), "0.000 s");
    EXPECT_EQ(format_duration(std::chrono::milliseconds(0)), "0.000 s");
    EXPECT_EQ(format_duration(std::chrono::milliseconds(320)), "0.320 s");
    EXPECT_EQ(format_duration(std::chrono::milliseconds(999)), "0.999 s");
    EXPECT_EQ(format_duration(std::chrono::milliseconds(4800)), "4.800 s");
    EXPECT_EQ(format_duration(std::chrono::milliseconds(5000)), "5.000 s");
    EXPECT_EQ(format_duration(std::chrono::seconds(72)), "72.000 s");
    EXPECT_EQ(format_duration(std::chrono::seconds(60)), "60.000 s");
    EXPECT_EQ(format_duration(std::chrono::seconds(125)), "125.000 s");
    EXPECT_EQ(format_duration(std::chrono::seconds(3665)), "3665.000 s");
}

TEST(CliPresenterTest, PresentsCancellationAsWarningWithExitCode130) {
    // Portuguese
    kasumi::cli::i18n::set_language(Language::Portuguese);
    {
        int code = 0;
        const auto output = kasumi::test::capture_stdout([&] {
            code = kasumi::cli::present_cancellation(Operation::Sync);
        });
        EXPECT_EQ(code, 130);
        EXPECT_NE(output.find("[AVISO]"), std::string::npos);
        EXPECT_NE(output.find("Sincronização cancelada pelo usuário."),
                  std::string::npos);
        EXPECT_EQ(output.find("[ERRO]"), std::string::npos);
        EXPECT_EQ(output.find("Sincronização finalizada com falhas"),
                  std::string::npos);
    }

    // English
    kasumi::cli::i18n::set_language(Language::English);
    {
        int code = 0;
        const auto output = kasumi::test::capture_stdout([&] {
            code = kasumi::cli::present_cancellation(Operation::Sync);
        });
        EXPECT_EQ(code, 130);
        EXPECT_NE(output.find("[WARNING]"), std::string::npos);
        EXPECT_NE(output.find("Synchronization cancelled by user."),
                  std::string::npos);
        EXPECT_EQ(output.find("[ERROR]"), std::string::npos);
    }

    // Automatic cancellation recognition via platform::cancellation
    kasumi::platform::cancellation::request();
    {
        int code = 0;
        const auto output = kasumi::test::capture_stdout([&] {
            const Error error{.operation = Operation::Sync,
                              .code = ErrorCode::SynchronizationFailure,
                              .detail = "operation cancelled by user"};
            code = kasumi::cli::present(error);
        });
        EXPECT_EQ(code, 130);
        EXPECT_NE(output.find("[WARNING]"), std::string::npos);
        EXPECT_NE(output.find("Synchronization cancelled by user."),
                  std::string::npos);
        EXPECT_EQ(output.find("[ERROR]"), std::string::npos);
    }
    kasumi::platform::cancellation::reset();
}

TEST(CliPresenterTest, PresentsErrorsWithStageContextInPortugueseAndEnglish) {
    kasumi::cli::i18n::set_language(Language::Portuguese);
    {
        const auto output = kasumi::test::capture_stdout([&] {
            const Error error{.operation = Operation::Sync,
                              .code = ErrorCode::PlanFailure,
                              .detail = "conexão recusada",
                              .stage = SyncStage::Observing};
            EXPECT_EQ(kasumi::cli::present(error), 1);
        });
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha durante a observação."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: conexão recusada"), std::string::npos);
    }

    {
        const auto output = kasumi::test::capture_stdout([&] {
            const Error error{.operation = Operation::Sync,
                              .code = ErrorCode::PlanFailure,
                              .detail = "conflito irrecuperável",
                              .stage = SyncStage::Calculating};
            EXPECT_EQ(kasumi::cli::present(error), 1);
        });
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha ao calcular alterações."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: conflito irrecuperável"),
                  std::string::npos);
    }

    {
        const auto output = kasumi::test::capture_stdout([&] {
            const Error error{.operation = Operation::Sync,
                              .code = ErrorCode::SynchronizationFailure,
                              .detail = "disco cheio",
                              .stage = SyncStage::Applying};
            EXPECT_EQ(kasumi::cli::present(error), 1);
        });
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha ao aplicar alterações."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: disco cheio"), std::string::npos);
    }

    {
        const auto output = kasumi::test::capture_stdout([&] {
            const Error error{.operation = Operation::Sync,
                              .code = ErrorCode::SynchronizationFailure,
                              .detail = "CommitUploaded falhou",
                              .stage = SyncStage::Publishing};
            EXPECT_EQ(kasumi::cli::present(error), 1);
        });
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha durante a publicação."),
                  std::string::npos);
        // Internal state name CommitUploaded sanitized
        EXPECT_EQ(output.find("CommitUploaded"), std::string::npos);
        EXPECT_NE(output.find("Motivo: commit publicado falhou"),
                  std::string::npos);
    }

    {
        const auto output = kasumi::test::capture_stdout([&] {
            const Error error{.operation = Operation::Sync,
                              .code = ErrorCode::SynchronizationFailure,
                              .detail = "falha de liberação",
                              .stage = SyncStage::Finalizing};
            EXPECT_EQ(kasumi::cli::present(error), 1);
        });
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha ao finalizar a sincronização."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: falha de liberação"), std::string::npos);
    }

    // English
    kasumi::cli::i18n::set_language(Language::English);
    {
        const auto output = kasumi::test::capture_stdout([&] {
            const Error error{.operation = Operation::Sync,
                              .code = ErrorCode::SynchronizationFailure,
                              .detail = "network timeout",
                              .stage = SyncStage::Publishing};
            EXPECT_EQ(kasumi::cli::present(error), 1);
        });
        EXPECT_NE(output.find("[ERROR]"), std::string::npos);
        EXPECT_NE(output.find("Failure during publication."),
                  std::string::npos);
        EXPECT_NE(output.find("Reason: network timeout"), std::string::npos);
    }
    {
        const auto output = kasumi::test::capture_stdout([&] {
            const Error error{.operation = Operation::Sync,
                              .code = ErrorCode::SynchronizationFailure,
                              .detail = "CommitUploaded failed",
                              .stage = SyncStage::Publishing};
            EXPECT_EQ(kasumi::cli::present(error), 1);
        });
        EXPECT_NE(output.find("[ERROR]"), std::string::npos);
        EXPECT_NE(output.find("Failure during publication."),
                  std::string::npos);
        EXPECT_EQ(output.find("CommitUploaded"), std::string::npos);
        EXPECT_NE(output.find("Reason: published commit failed"),
                  std::string::npos);
    }
}

TEST(CliPresenterTest, PresentsSyncSummaryWithoutEmbeddingDomainDuration) {
    kasumi::cli::i18n::set_language(Language::Portuguese);
    {
        const auto output = kasumi::test::capture_stdout([&] {
            SyncCompleted summary{
                .total = 137,
                .uploaded = 92,
                .downloaded = 31,
                .removed = 14,
                .renamed = 0,
                .created_dirs = 0,
                .removed_dirs = 0,
                .upload_bytes = 1524713390,  // 1.42 GB
                .download_bytes = 297795584, // 284 MB
                .published = true,
                .duration = std::chrono::milliseconds(4800),
            };

            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating,
                                              .summary = summary,
                                              .total_items = 137});
            EXPECT_EQ(kasumi::cli::present(response(summary, Operation::Sync)),
                      0);
        });
        EXPECT_NE(output.find(
                      "137 alterações | ↑ 92 (1.42 GB) | ↓ 31 (284 MB) | - 14"),
                  std::string::npos);
        EXPECT_NE(output.find("[OK]"), std::string::npos);
        EXPECT_NE(output.find("Sincronização concluída."), std::string::npos);
    }

    // English
    kasumi::cli::i18n::set_language(Language::English);
    {
        const auto output = kasumi::test::capture_stdout([&] {
            SyncCompleted summary{
                .total = 137,
                .uploaded = 92,
                .downloaded = 31,
                .removed = 14,
                .upload_bytes = 1524713390,
                .download_bytes = 297795584,
                .published = true,
                .duration = std::chrono::milliseconds(4800),
            };

            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating,
                                              .summary = summary,
                                              .total_items = 137});
            EXPECT_EQ(kasumi::cli::present(response(summary, Operation::Sync)),
                      0);
        });
        EXPECT_NE(
            output.find("137 changes | ↑ 92 (1.42 GB) | ↓ 31 (284 MB) | - 14"),
            std::string::npos);
        EXPECT_NE(output.find("[OK]"), std::string::npos);
        EXPECT_NE(output.find("Synchronization completed."), std::string::npos);
    }
}

TEST(CliPresenterTest, PresentsPlanProgressStagesInPortugueseAndEnglish) {
    // Portuguese
    kasumi::cli::i18n::set_language(Language::Portuguese);
    {
        const auto output = kasumi::test::capture_stdout([&] {
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Observing},
                                 Operation::Preview);
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating},
                                 Operation::Preview);
        });
        EXPECT_NE(output.find("[1/2] Observando estado local e remoto..."),
                  std::string::npos);
        EXPECT_NE(output.find("[2/2] Calculando alterações..."),
                  std::string::npos);
        EXPECT_EQ(output.find("[1/5]"), std::string::npos);
    }
    {
        const auto output = kasumi::test::capture_stdout([&] {
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Observing},
                                 Operation::Status);
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating},
                                 Operation::Status);
        });
        EXPECT_NE(output.find("[1/2] Observando estado local e remoto..."),
                  std::string::npos);
        EXPECT_NE(output.find("[2/2] Calculando alterações..."),
                  std::string::npos);
        EXPECT_EQ(output.find("[1/5]"), std::string::npos);
    }

    // English
    kasumi::cli::i18n::set_language(Language::English);
    {
        const auto output = kasumi::test::capture_stdout([&] {
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Observing},
                                 Operation::Preview);
            kasumi::cli::present(SyncProgress{.stage = SyncStage::Calculating},
                                 Operation::Preview);
        });
        EXPECT_NE(output.find("[1/2] Observing local and remote state..."),
                  std::string::npos);
        EXPECT_NE(output.find("[2/2] Calculating changes..."),
                  std::string::npos);
        EXPECT_EQ(output.find("[1/5]"), std::string::npos);
    }
}

TEST(CliPresenterTest, PresentsPlanErrorsWithStageContext) {
    const ScopedLanguage lang{Language::Portuguese};
    {
        const auto output = kasumi::test::capture_stdout([&] {
            const Error error{.operation = Operation::Status,
                              .code = ErrorCode::PlanFailure,
                              .detail = "falha na observação local",
                              .stage = SyncStage::Observing};
            EXPECT_EQ(kasumi::cli::present(error), 1);
        });
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha durante a observação."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: falha na observação local"),
                  std::string::npos);
    }
    {
        const auto output = kasumi::test::capture_stdout([&] {
            const Error error{.operation = Operation::Preview,
                              .code = ErrorCode::PlanFailure,
                              .detail = "conflito irrecuperável",
                              .stage = SyncStage::Calculating};
            EXPECT_EQ(kasumi::cli::present(error), 1);
        });
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha ao calcular alterações."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: conflito irrecuperável"),
                  std::string::npos);
    }
}

TEST(CliPresenterTest,
     PresentsPlanReportWithHeadTailTruncationWhenItemsExceedThreshold) {
    PlanReport report;
    for (int i = 0; i < 15; ++i) {
        report.items.push_back(
            {PlanAction::Upload, "file_" + std::to_string(i), {}, 10});
    }

    // Portuguese default (full = false)
    {
        const ScopedLanguage lang{Language::Portuguese};
        const auto output = present_out(response(report));

        for (int i = 0; i < 5; ++i) {
            EXPECT_NE(output.find("file_" + std::to_string(i)),
                      std::string::npos);
        }
        EXPECT_NE(output.find("... (mais 5 itens) ..."), std::string::npos);
        for (int i = 5; i < 10; ++i) {
            EXPECT_EQ(output.find("file_" + std::to_string(i)),
                      std::string::npos);
        }
        for (int i = 10; i < 15; ++i) {
            EXPECT_NE(output.find("file_" + std::to_string(i)),
                      std::string::npos);
        }
    }

    // English default (full = false)
    {
        const ScopedLanguage lang{Language::English};
        const auto output = present_out(response(report));

        EXPECT_NE(output.find("... (5 more items) ..."), std::string::npos);
    }
}

TEST(CliPresenterTest, PresentsPlanReportWithoutTruncationWhenFullFlagIsTrue) {
    PlanReport report;
    for (int i = 0; i < 15; ++i) {
        report.items.push_back(
            {PlanAction::Upload, "file_" + std::to_string(i), {}, 10});
    }

    const auto output = present_out(response(report), true);

    for (int i = 0; i < 15; ++i) {
        EXPECT_NE(output.find("file_" + std::to_string(i)), std::string::npos);
    }
    EXPECT_EQ(output.find("..."), std::string::npos);
}

TEST(CliPresenterTest,
     PresentsPlanReportWithoutTruncationWhenItemsAreTenOrLess) {
    PlanReport report;
    for (int i = 0; i < 10; ++i) {
        report.items.push_back(
            {PlanAction::Upload, "file_" + std::to_string(i), {}, 10});
    }

    const auto output = present_out(response(report), false);

    for (int i = 0; i < 10; ++i) {
        EXPECT_NE(output.find("file_" + std::to_string(i)), std::string::npos);
    }
    EXPECT_EQ(output.find("..."), std::string::npos);
}

TEST(CliPresenterTest,
     PresentsGarbageCollectProgressStagesAndSummaryInPortuguese) {
    const ScopedLanguage lang{Language::Portuguese};
    kasumi::cli::GarbageCollectProgressDisplayState state;

    const auto output = kasumi::test::capture_stdout([&] {
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Preparing},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing,
                                   .candidate_count = 8},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Applying},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Finalizing},
            state);
        GarbageCollectCompleted summary{
            .candidate_objects = 8,
            .analysis_only = false,
        };
        EXPECT_EQ(
            kasumi::cli::present(response(summary, Operation::GarbageCollect)),
            0);
    });
    EXPECT_NE(output.find("[1/4] Preparando coleta de lixo..."),
              std::string::npos);
    EXPECT_NE(output.find("[2/4] Analisando estado remoto..."),
              std::string::npos);
    EXPECT_NE(output.find("8 candidatos encontrados."), std::string::npos);
    EXPECT_NE(output.find("[3/4] Aplicando limpeza..."), std::string::npos);
    EXPECT_NE(output.find("[4/4] Finalizando..."), std::string::npos);
    EXPECT_NE(output.find("[OK]"), std::string::npos);
    EXPECT_NE(output.find("Coleta de lixo concluída."), std::string::npos);
    EXPECT_NE(output.find("8 objeto(s) candidato(s) analisado(s)."),
              std::string::npos);

    // Verify bounded output and no internal leaks
    EXPECT_EQ(output.find("[Running destination GC]"), std::string::npos);
    EXPECT_EQ(output.find("CommitPrepared"), std::string::npos);
}

TEST(CliPresenterTest,
     PresentsGarbageCollectProgressStagesAndSummaryInEnglish) {
    const ScopedLanguage lang{Language::English};
    kasumi::cli::GarbageCollectProgressDisplayState state;

    const auto output = kasumi::test::capture_stdout([&] {
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Preparing},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing,
                                   .candidate_count = 8},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Applying},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Finalizing},
            state);
        GarbageCollectCompleted summary{
            .candidate_objects = 8,
            .analysis_only = false,
        };
        EXPECT_EQ(
            kasumi::cli::present(response(summary, Operation::GarbageCollect)),
            0);
    });
    EXPECT_NE(output.find("[1/4] Preparing garbage collection..."),
              std::string::npos);
    EXPECT_NE(output.find("[2/4] Analyzing remote state..."),
              std::string::npos);
    EXPECT_NE(output.find("8 candidates found."), std::string::npos);
    EXPECT_NE(output.find("[3/4] Applying cleanup..."), std::string::npos);
    EXPECT_NE(output.find("[4/4] Finalizing..."), std::string::npos);
    EXPECT_NE(output.find("[OK]"), std::string::npos);
    EXPECT_NE(output.find("Garbage collection completed."), std::string::npos);
    EXPECT_EQ(output.find("Synchronization completed"), std::string::npos);
    EXPECT_NE(output.find("8 candidate object(s) analyzed."),
              std::string::npos);
    EXPECT_EQ(output.find("[Running destination GC]"), std::string::npos);
}

TEST(CliPresenterTest, DoesNotRepeatGarbageCollectProgressMessages) {
    const ScopedLanguage lang{Language::English};
    kasumi::cli::GarbageCollectProgressDisplayState state;

    const auto output = kasumi::test::capture_stdout([&] {
        for (int i = 0; i < 3; ++i) {
            kasumi::cli::present(
                GarbageCollectProgress{.stage = GarbageCollectStage::Preparing},
                state);
        }
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing},
            state);
        for (int i = 0; i < 2; ++i) {
            kasumi::cli::present(
                GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing,
                                       .candidate_count = 8},
                state);
        }
        for (int i = 0; i < 6; ++i) {
            kasumi::cli::present(
                GarbageCollectProgress{.stage = GarbageCollectStage::Applying},
                state);
        }
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Finalizing},
            state);
    });
    const auto expect_once = [&](const std::string& message) {
        const auto first = output.find(message);
        EXPECT_NE(first, std::string::npos);
        EXPECT_EQ(first, output.rfind(message));
    };

    expect_once("[1/4] Preparing garbage collection...");
    expect_once("[2/4] Analyzing remote state...");
    expect_once("8 candidates found.");
    expect_once("[3/4] Applying cleanup...");
    expect_once("[4/4] Finalizing...");
}

TEST(CliPresenterTest, GarbageCollectProgressStateIsPerExecution) {
    const ScopedLanguage lang{Language::English};
    kasumi::cli::GarbageCollectProgressDisplayState first_state;
    kasumi::cli::GarbageCollectProgressDisplayState second_state;

    const auto output = kasumi::test::capture_stdout([&] {
        for (auto* state : {&first_state, &second_state}) {
            kasumi::cli::present(
                GarbageCollectProgress{.stage = GarbageCollectStage::Preparing},
                *state);
            kasumi::cli::present(
                GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing},
                *state);
        }
    });
    for (const std::string message : {"[1/4] Preparing garbage collection...",
                                      "[2/4] Analyzing remote state..."}) {
        const auto first = output.find(message);
        const auto second = output.find(message, first + message.size());
        EXPECT_NE(first, std::string::npos);
        EXPECT_NE(second, std::string::npos);
        EXPECT_EQ(second, output.rfind(message));
    }
}

TEST(CliPresenterTest,
     PresentsGarbageCollectProgressNoCandidatesOmittingApplying) {
    const ScopedLanguage lang{Language::Portuguese};
    kasumi::cli::GarbageCollectProgressDisplayState state;

    const auto output = kasumi::test::capture_stdout([&] {
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Preparing},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing,
                                   .candidate_count = 0},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing,
                                   .candidate_count = 0},
            state);
        // Stage 3 (Applying) omitted when no destructive work is performed.
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Finalizing},
            state);
        GarbageCollectCompleted summary{
            .candidate_objects = 0,
            .analysis_only = false,
        };
        EXPECT_EQ(
            kasumi::cli::present(response(summary, Operation::GarbageCollect)),
            0);
    });
    EXPECT_NE(output.find("[1/4] Preparando coleta de lixo..."),
              std::string::npos);
    EXPECT_NE(output.find("[2/4] Analisando estado remoto..."),
              std::string::npos);
    EXPECT_NE(output.find("Nenhum candidato a coleta de lixo encontrado."),
              std::string::npos);
    EXPECT_EQ(output.find("Nenhum candidato a coleta de lixo encontrado."),
              output.rfind("Nenhum candidato a coleta de lixo encontrado."));
    EXPECT_EQ(output.find("[3/4]"), std::string::npos);
    EXPECT_NE(output.find("[4/4] Finalizando..."), std::string::npos);
    EXPECT_NE(output.find("[OK]"), std::string::npos);
    EXPECT_NE(output.find("0 objeto(s) candidato(s) analisado(s)."),
              std::string::npos);
}

TEST(CliPresenterTest, PresentsGarbageCollectProgressAnalysisOnlyWarning) {
    const ScopedLanguage lang{Language::English};
    kasumi::cli::GarbageCollectProgressDisplayState state;

    const auto output = kasumi::test::capture_stdout([&] {
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Preparing},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Analyzing,
                                   .candidate_count = 42},
            state);
        kasumi::cli::present(
            GarbageCollectProgress{.stage = GarbageCollectStage::Finalizing},
            state);
        GarbageCollectCompleted summary{
            .candidate_objects = 42,
            .analysis_only = true,
        };
        EXPECT_EQ(
            kasumi::cli::present(response(summary, Operation::GarbageCollect)),
            0);
    });
    EXPECT_NE(output.find("[1/4] Preparing garbage collection..."),
              std::string::npos);
    EXPECT_NE(output.find("[2/4] Analyzing remote state..."),
              std::string::npos);
    EXPECT_NE(output.find("42 candidates found."), std::string::npos);
    EXPECT_EQ(output.find("[3/4]"), std::string::npos);
    EXPECT_NE(output.find("[4/4] Finalizing..."), std::string::npos);
    EXPECT_NE(output.find("[WARNING]"), std::string::npos);
    EXPECT_NE(output.find("No candidate objects were removed."),
              std::string::npos);
    EXPECT_EQ(output.find("[OK]"), std::string::npos);
}

TEST(CliPresenterTest, GcDryRunPresentsBreakdownAndNoDeletions) {
    const ScopedLanguage lang{Language::English};
    const auto with_candidates = present_out(
        Response{.operation = Operation::GarbageCollect,
                 .data = GarbageCollectCompleted{
                     .candidate_objects = 5,
                     .dry_run = true,
                     .candidate_content_objects = 2,
                     .candidate_commit_variants = 2,
                     .candidate_activities = 1,
                 }});
    EXPECT_NE(
        with_candidates.find(
            "GC plan: 5 candidate(s) (2 content object(s), 2 commit "
            "variant(s), 1 activity record(s))."),
        std::string::npos);
    EXPECT_NE(
        with_candidates.find(
            "Garbage collection dry-run completed: no objects removed."),
        std::string::npos);

    const auto empty = present_out(
        Response{.operation = Operation::GarbageCollect,
                 .data = GarbageCollectCompleted{
                     .candidate_objects = 0,
                     .dry_run = true,
                 }});
    EXPECT_NE(empty.find("[OK] No garbage collection candidates found."),
              std::string::npos);
    EXPECT_NE(
        empty.find("Garbage collection dry-run completed: no objects removed."),
        std::string::npos);
}

TEST(CliPresenterTest, PresentsFsckProgressInPortugueseIncludingZeroBytes) {
    const ScopedLanguage lang{Language::Portuguese};
    kasumi::cli::FsckProgressDisplayState state;

    const auto output = kasumi::test::capture_stdout([&] {
        for (const auto stage : {FsckStage::Preparing,
                                 FsckStage::Observing,
                                 FsckStage::Analyzing}) {
            kasumi::cli::present(FsckProgress{.stage = stage}, state);
        }
        kasumi::cli::present(
            FsckProgress{
                .stage = FsckStage::AuditingContent,
                .completed_objects = 0,
                .total_objects = 1,
                .completed_plaintext_bytes = 0,
                .total_plaintext_bytes = 0,
            },
            state);
        kasumi::cli::present(
            FsckProgress{
                .stage = FsckStage::AuditingContent,
                .completed_objects = 1,
                .total_objects = 1,
                .completed_plaintext_bytes = 0,
                .total_plaintext_bytes = 0,
            },
            state);
        kasumi::cli::present(FsckProgress{.stage = FsckStage::Finalizing},
                             state);
    });

    EXPECT_NE(output.find("Preparando auditoria"), std::string::npos);
    EXPECT_NE(output.find("Observando histórico remoto"), std::string::npos);
    EXPECT_NE(output.find("Analisando inventário autenticado"),
              std::string::npos);
    EXPECT_NE(output.find("Auditando conteúdo referenciado"),
              std::string::npos);
    EXPECT_NE(output.find("Finalizando auditoria"), std::string::npos);
    EXPECT_NE(output.find("Auditado 0/1 objeto único (0%)"), std::string::npos);
    EXPECT_NE(output.find("0 bytes / 0 bytes"), std::string::npos);
    EXPECT_NE(output.find("100%"), std::string::npos);
}

TEST(CliPresenterTest, PresentsObjectAndBytePercentagesInEnglish) {
    const ScopedLanguage lang{Language::English};
    kasumi::cli::FsckProgressDisplayState state;

    const auto output = kasumi::test::capture_stdout([&] {
        kasumi::cli::present(
            FsckProgress{
                .stage = FsckStage::AuditingContent,
                .completed_objects = 1,
                .total_objects = 4,
                .completed_plaintext_bytes = 50,
                .total_plaintext_bytes = 100,
            },
            state);
        kasumi::cli::present(
            FsckProgress{
                .stage = FsckStage::AuditingContent,
                .completed_objects = 4,
                .total_objects = 4,
                .completed_plaintext_bytes = 100,
                .total_plaintext_bytes = 100,
            },
            state);
    });

    EXPECT_NE(output.find("1/4 unique objects (25%)"), std::string::npos);
    EXPECT_NE(output.find("50 bytes / 100 bytes (50%)"), std::string::npos);
    EXPECT_NE(output.find("4/4 unique objects (100%)"), std::string::npos);
    EXPECT_NE(output.find("100 bytes / 100 bytes (100%)"), std::string::npos);
    EXPECT_EQ(output.find("80%"),
              std::string::npos); // Stage 4/5 is not overall progress.
}

TEST(CliPresenterTest, BoundsFsckProgressOutputAndOmitsUnknownByteTotals) {
    const ScopedLanguage lang{Language::English};
    kasumi::cli::FsckProgressDisplayState state;

    const auto output = kasumi::test::capture_stdout([&] {
        for (const auto stage : {FsckStage::Preparing,
                                 FsckStage::Observing,
                                 FsckStage::Analyzing}) {
            kasumi::cli::present(FsckProgress{.stage = stage}, state);
        }
        for (std::size_t completed = 0; completed <= 10'000; ++completed) {
            kasumi::cli::present(
                FsckProgress{
                    .stage = FsckStage::AuditingContent,
                    .completed_objects = completed,
                    .total_objects = 10'000,
                    .completed_plaintext_bytes = std::nullopt,
                    .total_plaintext_bytes = std::nullopt,
                },
                state);
        }
        kasumi::cli::present(FsckProgress{.stage = FsckStage::Finalizing},
                             state);
    });

    EXPECT_LE(std::count(output.begin(), output.end(), '\n'), 120);
    EXPECT_NE(output.find("0%"), std::string::npos);
    EXPECT_NE(output.find("100%"), std::string::npos);
    EXPECT_NE(output.find("10000"), std::string::npos);
    EXPECT_NE(output.find("[1/5] Preparing integrity audit"),
              std::string::npos);
    EXPECT_NE(output.find("[2/5] Observing remote history"), std::string::npos);
    EXPECT_NE(output.find("[3/5] Analyzing authenticated inventory"),
              std::string::npos);
    EXPECT_NE(output.find("[4/5] Auditing referenced content"),
              std::string::npos);
    EXPECT_NE(output.find("[5/5] Finalizing audit"), std::string::npos);
    EXPECT_EQ(output.find("bytes"), std::string::npos);
}

TEST(CliPresenterTest, PresentsEmptyFsckInventoryWithoutAFalsePercentage) {
    const ScopedLanguage lang{Language::English};
    kasumi::cli::FsckProgressDisplayState state;

    const auto output = kasumi::test::capture_stdout([&] {
        kasumi::cli::present(
            FsckProgress{
                .stage = FsckStage::AuditingContent,
                .total_objects = 0,
                .completed_plaintext_bytes = 0,
                .total_plaintext_bytes = 0,
            },
            state);
    });
    EXPECT_NE(output.find("No referenced content objects"), std::string::npos);
    EXPECT_EQ(output.find("%"), std::string::npos);
}

TEST(CliPresenterTest, FullObjectProgressFollowedByFailureHasNoSuccessSummary) {
    const ScopedLanguage lang{Language::English};
    kasumi::cli::FsckProgressDisplayState state;
    const Error error{.operation = Operation::Fsck,
                      .code = ErrorCode::FsckFailure,
                      .detail = "corrupt content",
                      .runtime = std::nullopt};

    const auto output = kasumi::test::capture_stdout([&] {
        kasumi::cli::present(
            FsckProgress{
                .stage = FsckStage::AuditingContent,
                .completed_objects = 1,
                .total_objects = 1,
                .completed_plaintext_bytes = 6,
                .total_plaintext_bytes = 6,
            },
            state);
        kasumi::cli::present(error);
    });

    EXPECT_NE(output.find("100%"), std::string::npos);
    EXPECT_NE(output.find("Audit finished with failures"), std::string::npos);
    EXPECT_EQ(output.find("unique object audited"), std::string::npos);
    EXPECT_EQ(output.find("Expected plaintext:"), std::string::npos);
    EXPECT_EQ(output.find("Remote audit completed without failures."),
              std::string::npos);
}

TEST(CliPresenterTest,
     PresentsGarbageCollectCancellationAsWarningWithExitCode130) {
    const ScopedLanguage lang{Language::Portuguese};
    const auto output = kasumi::test::capture_stdout([&] {
        EXPECT_EQ(kasumi::cli::present_cancellation(Operation::GarbageCollect),
                  130);
    });
    EXPECT_NE(output.find("[AVISO]"), std::string::npos);
    EXPECT_NE(output.find("Operação cancelada pelo usuário."),
              std::string::npos);
}

TEST(CliPresenterTest, PresentsGarbageCollectBoundedOutputLines) {
    const ScopedLanguage lang{Language::English};
    kasumi::cli::GarbageCollectProgressDisplayState state;
    const auto repeat_progress = [&](GarbageCollectProgress progress) {
        for (int i = 0; i < 10000; ++i) {
            kasumi::cli::present(progress, state);
        }
    };

    const auto output = kasumi::test::capture_stdout([&] {
        repeat_progress({.stage = GarbageCollectStage::Preparing});
        repeat_progress({.stage = GarbageCollectStage::Analyzing,
                         .candidate_count = 100000});
        repeat_progress({.stage = GarbageCollectStage::Applying});
        repeat_progress({.stage = GarbageCollectStage::Finalizing});
        GarbageCollectCompleted summary{
            .candidate_objects = 100000,
            .analysis_only = false,
        };
        EXPECT_EQ(
            kasumi::cli::present(response(summary, Operation::GarbageCollect)),
            0);
    });
    const auto line_count = std::count(output.begin(), output.end(), '\n');
    EXPECT_LE(line_count, 12);
}

TEST(CliPresenterTest, RemoteWritersPresentsBarrierIdentifierWhenPresent) {
    const ScopedLanguage lang_en{Language::English};
    const auto output_en = present_out(InspectionResponse{
        .operation = InspectionOperation::RemoteWriters,
        .payload = RemoteWritersReport{.barrier_present = true,
                                       .barrier_identifier =
                                           "gc/v1/barrier/sample-barrier-id",
                                       .writers = {}}});
    EXPECT_NE(output_en.find("Barrier: present"), std::string::npos);
    EXPECT_NE(output_en.find("Identifier: gc/v1/barrier/sample-barrier-id"),
              std::string::npos);

    const ScopedLanguage lang_pt{Language::Portuguese};
    const auto output_pt = present_out(InspectionResponse{
        .operation = InspectionOperation::RemoteWriters,
        .payload = RemoteWritersReport{.barrier_present = true,
                                       .barrier_identifier =
                                           "gc/v1/barrier/sample-barrier-id",
                                       .writers = {}}});
    EXPECT_NE(output_pt.find("Barrier: presente"), std::string::npos);
    EXPECT_NE(output_pt.find("Identificador: gc/v1/barrier/sample-barrier-id"),
              std::string::npos);
}

TEST(CliPresenterTest, RemoteWritersOmitsBarrierIdentifierWhenAbsent) {
    const ScopedLanguage lang{Language::English};
    const auto output = present_out(InspectionResponse{
        .operation = InspectionOperation::RemoteWriters,
        .payload = RemoteWritersReport{.barrier_present = false,
                                       .barrier_identifier = std::nullopt,
                                       .writers = {}}});
    EXPECT_NE(output.find("Barrier: absent"), std::string::npos);
    EXPECT_EQ(output.find("Identifier:"), std::string::npos);
}

TEST(CliPresenterTest, ManualBarrierRemovalPresentation) {
    const ScopedLanguage lang{Language::English};

    const auto removed_clean =
        present_out(Response{.operation = Operation::RemoveBarrier,
                             .data = ManualBarrierRemovalCompleted{
                                 .identifier = "history/gc/v1/barrier",
                                 .outcome = BarrierRemovalOutcome::Removed,
                                 .active_writers_count = 0,
                             }});
    EXPECT_NE(removed_clean.find(
                  "Removed maintenance barrier: history/gc/v1/barrier"),
              std::string::npos);

    const auto removed_with_writers =
        present_out(Response{.operation = Operation::RemoveBarrier,
                             .data = ManualBarrierRemovalCompleted{
                                 .identifier = "history/gc/v1/barrier",
                                 .outcome = BarrierRemovalOutcome::Removed,
                                 .active_writers_count = 2,
                             }});
    EXPECT_NE(removed_with_writers.find(
                  "Removed maintenance barrier: history/gc/v1/barrier"),
              std::string::npos);
    EXPECT_NE(removed_with_writers.find("remove-writer"), std::string::npos);

    const auto absent = present_out(
        Response{.operation = Operation::RemoveBarrier,
                 .data = ManualBarrierRemovalCompleted{
                     .identifier = "history/gc/v1/barrier",
                     .outcome = BarrierRemovalOutcome::AlreadyAbsent,
                     .active_writers_count = 0,
                 }});
    EXPECT_NE(absent.find("already absent"), std::string::npos);
}

TEST(CliPresenterTest, ManualBarrierRemovalErrorPresentationWithDiagnostics) {
    const ScopedLanguage lang_en{Language::English};
    const auto output_en = present_out(
        Error{.operation = Operation::RemoveBarrier,
              .code = ErrorCode::BarrierRemovalFailure,
              .detail =
                  "could not remove maintenance barrier: transport error: "
                  "timeout: connection reset (native_code=10054)",
              .barrier_removal =
                  BarrierRemovalFailure{
                      .barrier_identifier = "gc/v1/barrier",
                      .stage = BarrierRemovalStage::Removing,
                      .mutation_state = BarrierRemovalMutationState::Uncertain,
                      .transport_error =
                          kasumi::transport::Error{
                              .code = kasumi::transport::ErrorCode::Timeout,
                              .message = "connection reset",
                              .native_code = 10054,
                          },
                  }},
        1);
    EXPECT_NE(output_en.find("Failed to remove maintenance barrier"),
              std::string::npos);
    EXPECT_NE(output_en.find("Stage: Removing barrier"), std::string::npos);
    EXPECT_NE(output_en.find("Mutation state: Uncertain"), std::string::npos);
    EXPECT_NE(
        output_en.find(
            "Transport error: timeout: connection reset (native_code=10054)"),
        std::string::npos);

    const ScopedLanguage lang_pt{Language::Portuguese};
    const auto output_pt = present_out(
        Error{.operation = Operation::RemoveBarrier,
              .code = ErrorCode::BarrierRemovalFailure,
              .detail = "could not remove maintenance barrier",
              .barrier_removal =
                  BarrierRemovalFailure{
                      .barrier_identifier = "gc/v1/barrier",
                      .stage = BarrierRemovalStage::ConfirmingAbsence,
                      .mutation_state = BarrierRemovalMutationState::Uncertain,
                      .transport_error =
                          kasumi::transport::Error{
                              .code = kasumi::transport::ErrorCode::Io,
                              .message = "disk full",
                              .native_code = 28,
                          },
                  }},
        1);
    EXPECT_NE(output_pt.find("Etapa: Confirmando ausência da barreira"),
              std::string::npos);
    EXPECT_NE(output_pt.find("Estado da mutação: Incerta"), std::string::npos);
    EXPECT_NE(
        output_pt.find("Erro de transporte: io: disk full (native_code=28)"),
        std::string::npos);
}

TEST(CliPresenterTest, RepackPresentationCoversNoOpDryRunAndPublish) {
    {
        const ScopedLanguage lang_en{Language::English};
        const auto noop_with_dirty = present_out(
            Response{
                .operation = Operation::Repack,
                .data = RepackCompleted{
                    .actionable = false,
                    .existing_packs = 3,
                    .healthy_packs_kept = 2,
                    .dirty_packs_detected = 1,
                    .loose_small_blobs_detected = 1,
                }},
            true);
        EXPECT_NE(noop_with_dirty.find("Nothing to repack"), std::string::npos);
        EXPECT_NE(noop_with_dirty.find("--reclaim-dirty"), std::string::npos);
        EXPECT_NE(noop_with_dirty.find("Inventory: 3 existing pack(s)"),
                  std::string::npos);

        const auto dry_run = present_out(
            Response{
                .operation = Operation::Repack,
                .data = RepackCompleted{
                    .dry_run = true,
                    .actionable = true,
                    .existing_packs = 1,
                    .healthy_packs_kept = 0,
                    .dirty_packs_detected = 0,
                    .loose_small_blobs_detected = 2,
                    .source_loose_blobs = 2,
                    .source_clean_packs = 1,
                    .source_dirty_packs = 0,
                    .new_packs = 1,
                    .repacked_blobs = 4,
                    .repacked_plaintext_bytes = 2048,
                }},
            false);
        EXPECT_NE(dry_run.find("Repack plan: 4 blob(s) (2 KB) -> 1 new Micro-Pack(s)."),
                  std::string::npos);
        EXPECT_NE(dry_run.find("Sources: 2 loose blob(s), 1 underfilled pack(s), 0 dirty pack(s)."),
                  std::string::npos);
        EXPECT_NE(dry_run.find("Repack dry-run completed"), std::string::npos);
        EXPECT_EQ(dry_run.find("Inventory:"), std::string::npos);

        const auto published = present_out(
            Response{
                .operation = Operation::Repack,
                .data = RepackCompleted{
                    .dry_run = false,
                    .actionable = true,
                    .published = true,
                    .existing_packs = 2,
                    .healthy_packs_kept = 1,
                    .dirty_packs_detected = 1,
                    .loose_small_blobs_detected = 3,
                    .source_loose_blobs = 3,
                    .source_clean_packs = 0,
                    .source_dirty_packs = 1,
                    .new_packs = 1,
                    .repacked_blobs = 5,
                    .repacked_plaintext_bytes = 4096,
                    .published_commit_id = std::string(64, 'a'),
                    .published_height = 7,
                    .wire_upload_bytes = 5120,
                    .physical_objects_uploaded = 3,
                }},
            true);
        EXPECT_NE(published.find("[OK] Repack completed."), std::string::npos);
        EXPECT_NE(published.find("Wire upload 5 KB (3 objects)"),
                  std::string::npos);
        EXPECT_NE(published.find("Published commit: "), std::string::npos);
        EXPECT_NE(published.find("(height 7)"), std::string::npos);
        EXPECT_NE(published.find("kasumi gc"), std::string::npos);

        EXPECT_EQ(kasumi::cli::present(
                      Response{.operation = Operation::Sync,
                               .data = RepackCompleted{}}),
                  1);
        const auto failed = present_out(
            Error{.operation = Operation::Repack,
                  .code = ErrorCode::RepackFailure,
                  .detail = "workspace dirty"},
            1);
        EXPECT_NE(failed.find("Repack failed: workspace dirty"),
                  std::string::npos);
        const auto cancelled = kasumi::test::capture_stdout([&] {
            EXPECT_EQ(kasumi::cli::present_cancellation(Operation::Repack),
                      130);
        });
        EXPECT_NE(cancelled.find("Operation cancelled by user."),
                  std::string::npos);
    }

    const ScopedLanguage lang_pt{Language::Portuguese};
    const auto pt_published = present_out(
        Response{
            .operation = Operation::Repack,
            .data = RepackCompleted{
                .dry_run = false,
                .actionable = true,
                .published = true,
                .source_loose_blobs = 2,
                .source_clean_packs = 1,
                .new_packs = 1,
                .repacked_blobs = 3,
                .repacked_plaintext_bytes = 1024,
                .published_commit_id = std::string(64, 'b'),
                .published_height = 2,
                .wire_upload_bytes = 2048,
                .physical_objects_uploaded = 1,
            }},
        true);
    EXPECT_NE(pt_published.find("[OK] Repack concluído."), std::string::npos);
    EXPECT_NE(pt_published.find("Envio real 2 KB (1 objeto)"), std::string::npos);
    EXPECT_NE(pt_published.find("Commit publicado: "), std::string::npos);
    EXPECT_NE(pt_published.find("(altura 2)"), std::string::npos);
    const auto pt_failed = present_out(
        Error{.operation = Operation::Repack,
              .code = ErrorCode::RepackFailure,
              .detail = "conflito"},
        1);
    EXPECT_NE(pt_failed.find("Falha no repack: conflito"), std::string::npos);
}
} // namespace

TEST(CliPresenterTest, ResolveMissingSuccessIsLocalized) {
    kasumi::cli::i18n::set_language(Language::Portuguese);
    const auto resolved = present_out(
        Response{.operation = Operation::ResolveMissing,
                 .data = ResolveMissingCompleted{.resolved_count = 2}});
    EXPECT_NE(resolved.find("2 caminhos ausentes resolvidos"),
              std::string::npos);
    const auto empty =
        present_out(Response{.operation = Operation::ResolveMissing,
                             .data = ResolveMissingCompleted{}});
    EXPECT_NE(empty.find("Nenhum caminho ausente pendente para resolver"),
              std::string::npos);
    kasumi::cli::i18n::set_language(Language::English);
}

TEST(CliPresenterTest, SanitizesTerminalControlAndEscapeSequences) {
    const std::string dirty = "bad\x1b[31mpath\x07\r\nnext\t\x7f\xc2\x9b"
                              "ok";
    const auto cleaned = kasumi::cli::sanitize_terminal_text(dirty);
    EXPECT_EQ(cleaned.find('\x1b'), std::string::npos);
    EXPECT_EQ(cleaned.find('\x07'), std::string::npos);
    EXPECT_EQ(cleaned.find('\r'), std::string::npos);
    EXPECT_EQ(cleaned.find('\x7f'), std::string::npos);
    EXPECT_EQ(cleaned.find("\xc2\x9b"), std::string::npos);
    EXPECT_EQ(cleaned, "bad?[31mpath??\nnext\t??ok");
}

TEST(CliPresenterTest, RemoteObjectsRenderExternalFieldsAsSingleSafeLines) {
    using namespace kasumi::application;
    const auto output = present_out(InspectionResponse{
        .operation = InspectionOperation::RemoteObjects,
        .payload = RemoteObjectsReport{
            .objects = {{.identifier = "relatório/\x1b[2J\x9b"
                                       "2J",
                         .relation = "reason\nforged\tline"}}}});
    EXPECT_TRUE(output.contains("relatório/?[2J?2J"));
    EXPECT_TRUE(output.contains("reason?forged?line"));
}

TEST(CliPresenterTest,
     RemoteHeadsCommitsAndCommitFormatTimestampsAndAuthorship) {
    using namespace kasumi::application;
    const std::int64_t ts_a = 1700000100;
    const std::int64_t ts_b = 1700000200;
    const auto formatted_a =
        kasumi::platform::clock::format_local_timestamp(ts_a);
    const auto formatted_b =
        kasumi::platform::clock::format_local_timestamp(ts_b);
    const std::string id_a = "aaaa1111222233334444555566667777";
    const std::string id_b = "bbbb1111222233334444555566667777";
    const std::string id_c = "cccc1111222233334444555566667777";

    const ScopedLanguage lang{Language::English};
    const auto heads_out = present_out(InspectionResponse{
        .operation = InspectionOperation::RemoteHeads,
        .payload = RemoteHeadsReport{
            .history_present = true,
            .observed_height = 5,
            .heads = {
                RemoteHeadInfo{
                    .commit_id = std::string(64, '1'),
                    .height = 5,
                    .created_at = ts_a,
                    .root_hash = std::string(64, '2'),
                    .authorship =
                        RemoteCommitAuthorship{
                            .operation = RemoteCommitOrigin::Sync,
                            .machine_id_hex = id_a,
                            .machine_name = "workstation",
                        },
                },
                RemoteHeadInfo{
                    .commit_id = std::string(64, '3'),
                    .height = 5,
                    .created_at = ts_b,
                    .root_hash = std::string(64, '4'),
                    .authorship =
                        RemoteCommitAuthorship{
                            .operation = RemoteCommitOrigin::Repack,
                            .machine_id_hex = id_b,
                            .machine_name = "workstation",
                        },
                },
            }}});
    EXPECT_NE(heads_out.find("Created at: " + formatted_a), std::string::npos);
    EXPECT_NE(heads_out.find("Created at: " + formatted_b), std::string::npos);
    EXPECT_NE(heads_out.find("Origin: sync"), std::string::npos);
    EXPECT_NE(heads_out.find("Origin: repack"), std::string::npos);
    EXPECT_NE(heads_out.find("Machine: workstation [aaaa]"), std::string::npos);
    EXPECT_NE(heads_out.find("Machine: workstation [bbbb]"), std::string::npos);

    const auto commits_out = present_out(InspectionResponse{
        .operation = InspectionOperation::RemoteCommits,
        .payload = RemoteCommitsReport{
            .history_present = true,
            .observed_height = 2,
            .commits = {
                RemoteCommitInfo{
                    .commit_id = std::string(64, '5'),
                    .height = 2,
                    .created_at = ts_b,
                    .logical_head = true,
                    .authorship =
                        RemoteCommitAuthorship{
                            .operation = RemoteCommitOrigin::ResolveMissing,
                            .machine_id_hex = id_c,
                            .machine_name = "laptop",
                        },
                },
                RemoteCommitInfo{
                    .commit_id = std::string(64, '6'),
                    .height = 1,
                    .created_at = ts_a,
                    .authorship = std::nullopt,
                },
            }}});
    EXPECT_NE(commits_out.find("Origin: resolve-missing"), std::string::npos);
    EXPECT_NE(commits_out.find("Machine: laptop\n"), std::string::npos);
    EXPECT_EQ(commits_out.find("laptop [cccc]"), std::string::npos);
    EXPECT_NE(commits_out.find("Origin: unknown"), std::string::npos);
    EXPECT_NE(commits_out.find("Machine: unknown"), std::string::npos);

    const auto commit_out = present_out(InspectionResponse{
        .operation = InspectionOperation::RemoteCommit,
        .payload = RemoteCommitReport{
            .commit = RemoteCommitInfo{
                .commit_id = std::string(64, '5'),
                .height = 2,
                .created_at = ts_b,
                .authorship =
                    RemoteCommitAuthorship{
                        .operation = RemoteCommitOrigin::Sync,
                        .machine_id_hex = id_c,
                        .machine_name = "laptop",
                    },
            }}});
    EXPECT_NE(commit_out.find("Created at: " + formatted_b), std::string::npos);
    EXPECT_NE(commit_out.find("Machine: laptop [cccc]"), std::string::npos);
}

TEST(CliPresenterTest,
     RemoteSummaryFullActivityReportAndObjectCategoryWorkCleanly) {
    using namespace kasumi::application;
    const std::string id_a = "aaaa1111222233334444555566667777";
    const std::string id_b = "bbbb1111222233334444555566667777";
    const InspectionResponse summary_resp{
        .operation = InspectionOperation::RemoteSummary,
        .payload = RemoteSummaryReport{
            .history_present = true,
            .observed_height = 4,
            .reachable_commit_count = 4,
            .logical_head_count = 1,
            .recent_activities = {
                RemoteActivityInfo{
                    .event_id = "00000000000000000000000000000001",
                    .operation = RemoteActivityOperation::Fsck,
                    .outcome = RemoteActivityOutcome::IssuesFound,
                    .machine_id_hex = id_a,
                    .machine_name = "host-a",
                    .started_at = 1700000000,
                    .finished_at = 1700000010,
                    .duration_ms = 2500,
                    .metric_primary = 5,
                    .metric_bytes = 2048,
                    .stage = "audit",
                    .detail = "missing blob",
                },
                RemoteActivityInfo{
                    .event_id = "00000000000000000000000000000002",
                    .operation = RemoteActivityOperation::Fsck,
                    .outcome = RemoteActivityOutcome::Succeeded,
                    .machine_id_hex = id_b,
                    .machine_name = "host-b",
                    .started_at = 1700000100,
                    .finished_at = 1700000110,
                    .duration_ms = 1200,
                    .metric_primary = 8,
                    .metric_bytes = 4096,
                },
                RemoteActivityInfo{
                    .event_id = "00000000000000000000000000000003",
                    .operation = RemoteActivityOperation::GarbageCollect,
                    .outcome = RemoteActivityOutcome::Succeeded,
                    .machine_id_hex = id_a,
                    .machine_name = "host-a",
                    .started_at = 1700000200,
                    .finished_at = 1700000210,
                    .duration_ms = 500,
                    .metric_primary = 0,
                    .metric_secondary = 3,
                    .flags = remote_activity_flag_analysis_only,
                },
            },
            .invalid_activity_count = 2,
        }};

    {
        const ScopedLanguage en{Language::English};
        const auto brief = kasumi::test::capture_stdout([&] {
            EXPECT_EQ(kasumi::cli::present(summary_resp, false), 0);
        });
        EXPECT_NE(brief.find("Invalid activity records: 2"), std::string::npos);
        EXPECT_NE(brief.find("Recent operational activity (2):"),
                  std::string::npos);
        EXPECT_NE(brief.find("3 record(s) total; use --full"),
                  std::string::npos);
        EXPECT_NE(brief.find("host-b"), std::string::npos);
        EXPECT_EQ(brief.find("missing blob"), std::string::npos);

        const auto detailed = kasumi::test::capture_stdout([&] {
            EXPECT_EQ(kasumi::cli::present(summary_resp, true), 0);
        });
        EXPECT_NE(detailed.find("Recent operational activity (3):"),
                  std::string::npos);
        EXPECT_NE(detailed.find(id_a), std::string::npos);
        EXPECT_NE(detailed.find("audit: missing blob"), std::string::npos);
        EXPECT_NE(detailed.find("analysis only"), std::string::npos);
        EXPECT_EQ(detailed.find("use --full"), std::string::npos);

        const auto obj_out = present_out(InspectionResponse{
            .operation = InspectionOperation::RemoteObjects,
            .payload = RemoteObjectsReport{
                .objects = {{.identifier = "act-obj",
                             .category = RemoteObjectCategory::Activity,
                             .structurally_valid = true}}}});
        EXPECT_NE(obj_out.find("Category: activity"), std::string::npos);
    }

    const ScopedLanguage pt{Language::Portuguese};
    const auto pt_brief = kasumi::test::capture_stdout([&] {
        EXPECT_EQ(kasumi::cli::present(summary_resp, false), 0);
    });
    EXPECT_NE(pt_brief.find("Registros de atividade inválidos: 2"),
              std::string::npos);
    EXPECT_NE(pt_brief.find("3 registro(s) no total; use --full"),
              std::string::npos);
}

TEST(CliPresenterTest,
     SyncDefaultStdoutUnchangedAndActivityPublishWarningUsesStderr) {
    using namespace kasumi::application;
    const ScopedLanguage en{Language::English};
    auto sync_resp = response(SyncCompleted{}, Operation::Sync);
    sync_resp.activity_publish_warning = "remote write denied";

    testing::internal::CaptureStdout();
    testing::internal::CaptureStderr();
    EXPECT_EQ(kasumi::cli::present(sync_resp, false), 0);
    const auto out = testing::internal::GetCapturedStdout();
    const auto err = testing::internal::GetCapturedStderr();
    EXPECT_EQ(out, "[OK] Synchronization completed.\n");
    EXPECT_NE(err.find("[WARNING]"), std::string::npos);
    EXPECT_NE(err.find("remote write denied"), std::string::npos);
}
