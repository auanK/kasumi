#include "application/inspection/result.hpp"
#include "cli/i18n.hpp"
#include "cli/presenter.hpp"
#include "platform/cancellation.hpp"

#include <gtest/gtest.h>
#include <string>
#include <utility>

namespace {

using namespace kasumi::application;

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

TEST(CliPresenterTest, PresentsEmptyAndPopulatedPlansWithTrafficAndRename) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response(PlanReport{})), 0);
    const auto empty_output = testing::internal::GetCapturedStdout();
    EXPECT_NE(empty_output.find("Nada a fazer"), std::string::npos);
    PlanReport report;
    report.has_conflicts = true;
    report.upload_bytes = 10;
    report.download_bytes = 20;
    report.items = {{PlanAction::RenameLocal, "old", "new", 0},
                    {PlanAction::Upload, "file", {}, 10},
                    {PlanAction::Download, "other", {}, 20}};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response(report)), 0);
    const auto output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("modificações independentes"), std::string::npos);
    EXPECT_NE(output.find("old -> new"), std::string::npos);
    EXPECT_NE(output.find("Upload"), std::string::npos);
    EXPECT_NE(output.find("20 bytes"), std::string::npos);
}

TEST(CliPresenterTest, PresentsSuccessfulResponseVariants) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response(SyncCompleted{}, Operation::Sync)),
              0);
    const auto sync_output = testing::internal::GetCapturedStdout();
    EXPECT_NE(sync_output.find("[OK]"), std::string::npos);
    EXPECT_NE(sync_output.find("Sincronização concluída."), std::string::npos);
    EXPECT_EQ(sync_output.find("sem erros"), std::string::npos);
    EXPECT_EQ(sync_output.find("Local:"), std::string::npos);
    EXPECT_EQ(sync_output.find("Destino:"), std::string::npos);

    EXPECT_EQ(kasumi::cli::present(response(FsckCompleted{}, Operation::Fsck)),
              0);
    EXPECT_EQ(kasumi::cli::present(
                  response(GarbageCollectCompleted{.candidate_objects = 3,
                                                   .quarantined_objects = 3},
                           Operation::GarbageCollect)),
              0);
}

TEST(CliPresenterTest, PresentsSynchronizationErrorsWithoutSecrets) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
    const Error error{.operation = Operation::Sync,
                      .code = ErrorCode::SynchronizationFailure,
                      .detail = "falha controlada",
                      .runtime = std::nullopt};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(error), 1);
    const auto output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("falha controlada"), std::string::npos);
}

TEST(CliPresenterTest, PresentsRemoteHeadsSemantically) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
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

    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(InspectionResponse{}), 0);
    const auto empty = testing::internal::GetCapturedStdout();
    EXPECT_EQ(empty, "Nenhuma head remota publicada.\n");
    EXPECT_TRUE(std::holds_alternative<RemoteHeadsReport>(
        InspectionResponse{}.payload));

    InspectionResponse response{
        .payload = RemoteHeadsReport{.history_present = true,
                                     .observed_height = 9,
                                     .heads = {first, second}}};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response), 0);
    const auto output = testing::internal::GetCapturedStdout();
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
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
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

    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response), 0);
    const auto output = testing::internal::GetCapturedStdout();
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
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
    const InspectionResponse empty{.operation =
                                       InspectionOperation::RemoteCommits,
                                   .payload = RemoteCommitsReport{}};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(empty), 0);
    const auto empty_output = testing::internal::GetCapturedStdout();
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

    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response), 0);
    const auto output = testing::internal::GetCapturedStdout();
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
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
    const InspectionError multiple{
        .operation = InspectionOperation::RemoteTree,
        .code = InspectionErrorCode::HeadSelectionRequired,
        .detail = "Remote history has multiple logical heads.",
        .candidate_ids = {"head-a", "head-b"}};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(multiple), 1);
    const auto multiple_output = testing::internal::GetCapturedStdout();
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
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(missing), 1);
    const auto missing_output = testing::internal::GetCapturedStdout();
    EXPECT_NE(missing_output.find(
                  "requested head is not among current logical heads"),
              std::string::npos);
    EXPECT_NE(missing_output.find("head-a"), std::string::npos);
}

TEST(CliPresenterTest, RejectsIncoherentInspectionPayloadWithoutThrowing) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
    const InspectionResponse response{.operation =
                                          InspectionOperation::RemoteTree,
                                      .payload = RemoteHeadsReport{}};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response), 1);
    const auto output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("resposta de inspeção inconsistente"),
              std::string::npos);
}

TEST(CliPresenterTest, PresentsRemoteSummarySemantically) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
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
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response), 0);
    const auto output = testing::internal::GetCapturedStdout();
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
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
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
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response), 0);
    const auto output = testing::internal::GetCapturedStdout();
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
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
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
                    .object_identifier = "history/commits/commit/a.kcom",
                    .state = RemoteCommitVariantState::Valid},
                RemoteCommitVariantInfo{
                    .ciphertext_id = "b",
                    .object_identifier = "history/commits/commit/b.kcom",
                    .state = RemoteCommitVariantState::InvalidCiphertext},
                RemoteCommitVariantInfo{
                    .ciphertext_id = "c",
                    .object_identifier = "history/commits/commit/c.kcom",
                    .state = RemoteCommitVariantState::InvalidCommit},
            }}};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response), 0);
    const auto output = testing::internal::GetCapturedStdout();
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
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
    const InspectionResponse response{
        .operation = InspectionOperation::RemoteGet,
        .payload =
            RemoteFileReport{.path = "docs/relatório.pdf",
                             .destination_path = "download/relatório.pdf",
                             .logical_hash = "logical-hash",
                             .content_id = "content-id",
                             .size = 42}};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response), 0);
    const auto output = testing::internal::GetCapturedStdout();
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
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
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
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(InspectionResponse{
                  .operation = InspectionOperation::RemoteEpochs,
                  .payload = RemoteEpochsReport{.epochs = {epoch}}}),
              0);
    const auto list_output = testing::internal::GetCapturedStdout();
    EXPECT_NE(list_output.find("Epochs remotos: 1"), std::string::npos);
    EXPECT_NE(list_output.find("Vault ID: vault-id"), std::string::npos);
    EXPECT_NE(list_output.find("Retenção mínima: 5 commit(s), 6 hora(s)"),
              std::string::npos);
    EXPECT_NE(list_output.find("commit-id (altura 9)"), std::string::npos);
    EXPECT_NE(list_output.find("Epoch anterior: previous-id"),
              std::string::npos);
    EXPECT_NE(list_output.find("Próximo Epoch: next-id"), std::string::npos);

    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(InspectionResponse{
                  .operation = InspectionOperation::RemoteEpoch,
                  .payload = RemoteEpochReport{.epoch = std::move(epoch)}}),
              0);
    EXPECT_NE(testing::internal::GetCapturedStdout().find("Epoch remoto"),
              std::string::npos);
}

TEST(CliPresenterTest, PresentsContentInventoryAuditAndDetail) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
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
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(InspectionResponse{
                  .operation = InspectionOperation::RemoteContentsAudit,
                  .payload = RemoteContentsReport{.audited = true,
                                                  .referenced_count = 1,
                                                  .physical_count = 1,
                                                  .valid_count = 1,
                                                  .contents = {content}}}),
              0);
    const auto audit_output = testing::internal::GetCapturedStdout();
    EXPECT_NE(audit_output.find("auditoria profunda"), std::string::npos);
    EXPECT_NE(audit_output.find("Válidos: 1"), std::string::npos);
    EXPECT_NE(audit_output.find("Estado: válido"), std::string::npos);
    EXPECT_NE(audit_output.find("docs/a.txt"), std::string::npos);

    testing::internal::CaptureStdout();
    EXPECT_EQ(
        kasumi::cli::present(InspectionResponse{
            .operation = InspectionOperation::RemoteContent,
            .payload = RemoteContentReport{.content = std::move(content)}}),
        0);
    const auto detail_output = testing::internal::GetCapturedStdout();
    EXPECT_NE(detail_output.find("Conteúdo remoto"), std::string::npos);
    EXPECT_NE(detail_output.find("Content ID: content-id"), std::string::npos);
}

TEST(CliPresenterTest, PresentsEveryPhysicalInspectionReportInPortuguese) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
    const auto present_and_capture = [](InspectionResponse response) {
        testing::internal::CaptureStdout();
        EXPECT_EQ(kasumi::cli::present(response), 0);
        const auto output = testing::internal::GetCapturedStdout();
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

    const auto quarantine = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteQuarantine,
        .payload = RemoteQuarantineReport{
            .entries = {{.original_identifier = "original",
                         .quarantine_identifier = "quarentena",
                         .metadata_identifier = "metadata",
                         .category = "content",
                         .metadata_authenticated = true,
                         .quarantined_at = 7}}}});
    EXPECT_NE(quarantine.find("Metadata autenticada: sim"), std::string::npos);
    EXPECT_NE(quarantine.find("nada será restaurado ou purgado"),
              std::string::npos);

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
    const ScopedLanguage lang{kasumi::cli::i18n::Language::English};
    const auto present_and_capture = [](InspectionResponse response) {
        testing::internal::CaptureStdout();
        EXPECT_EQ(kasumi::cli::present(response), 0);
        const auto output = testing::internal::GetCapturedStdout();
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

    const auto quarantine = present_and_capture(InspectionResponse{
        .operation = InspectionOperation::RemoteQuarantine,
        .payload = RemoteQuarantineReport{
            .entries = {{.original_identifier = "original",
                         .quarantine_identifier = "quarantine",
                         .metadata_identifier = "metadata",
                         .category = "content",
                         .metadata_authenticated = true,
                         .quarantined_at = 7}}}});
    EXPECT_NE(quarantine.find("Authenticated metadata: yes"),
              std::string::npos);
    EXPECT_NE(quarantine.find("nothing will be restored or purged"),
              std::string::npos);

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
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
    for (const auto code : {InspectionErrorCode::RemotePathNotFound,
                            InspectionErrorCode::RemoteCommitNotFound,
                            InspectionErrorCode::RemotePathIsDirectory,
                            InspectionErrorCode::RemoteContentNotFound,
                            InspectionErrorCode::RemoteContentInvalid,
                            InspectionErrorCode::DestinationFailure,
                            InspectionErrorCode::RemoteEpochNotFound}) {
        testing::internal::CaptureStdout();
        EXPECT_EQ(kasumi::cli::present(InspectionError{
                      .operation = InspectionOperation::RemoteStat,
                      .code = code,
                      .detail = "not found"}),
                  1);
        EXPECT_NE(testing::internal::GetCapturedStdout().find("not found"),
                  std::string::npos);
    }
}

TEST(CliPresenterTest, PresentsOutputsInEnglishWhenConfigured) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::English};

    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response(PlanReport{})), 0);
    const auto empty_output = testing::internal::GetCapturedStdout();
    EXPECT_NE(empty_output.find("Nothing to do"), std::string::npos);

    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response(SyncCompleted{}, Operation::Sync)),
              0);
    const auto sync_output = testing::internal::GetCapturedStdout();
    EXPECT_NE(sync_output.find("Synchronization completed."),
              std::string::npos);

    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(InspectionResponse{}), 0);
    const auto heads_empty = testing::internal::GetCapturedStdout();
    EXPECT_NE(heads_empty.find("No remote heads published."),
              std::string::npos);
}

TEST(CliPresenterTest, PresentsSyncProgressStagesAndSummaryInPortuguese) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};

    testing::internal::CaptureStdout();
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Observing});
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Calculating});
    kasumi::application::SyncCompleted summary{
        .total = 137,
        .uploaded = 92,
        .downloaded = 31,
        .removed = 14,
        .renamed = 0,
        .created_dirs = 0,
        .removed_dirs = 0,
        .published = true,
    };
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Calculating,
        .summary = summary,
        .total_items = 137});
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Applying, .total_items = 137});
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Publishing});
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Finalizing});
    EXPECT_EQ(kasumi::cli::present(
                  response(summary, kasumi::application::Operation::Sync)),
              0);

    const auto output = testing::internal::GetCapturedStdout();
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
    const ScopedLanguage lang{kasumi::cli::i18n::Language::English};

    testing::internal::CaptureStdout();
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Observing});
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Calculating});
    kasumi::application::SyncCompleted summary{
        .total = 5,
        .uploaded = 2,
        .downloaded = 1,
        .removed = 1,
        .renamed = 1,
        .created_dirs = 0,
        .removed_dirs = 0,
        .published = false,
    };
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Calculating,
        .summary = summary,
        .total_items = 5});
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Applying, .total_items = 5});
    // Stage 4 (Publishing) omitted when publication is not required
    kasumi::cli::present(kasumi::application::SyncProgress{
        .stage = kasumi::application::SyncStage::Finalizing});
    EXPECT_EQ(kasumi::cli::present(
                  response(summary, kasumi::application::Operation::Sync)),
              0);

    const auto output = testing::internal::GetCapturedStdout();
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
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::Portuguese);
    {
        testing::internal::CaptureStdout();
        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Observing});
        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Calculating});
        kasumi::application::SyncCompleted empty_summary{};
        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Calculating,
            .summary = empty_summary});
        EXPECT_EQ(kasumi::cli::present(response(
                      empty_summary, kasumi::application::Operation::Sync)),
                  0);

        const auto output = testing::internal::GetCapturedStdout();
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

    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
    {
        testing::internal::CaptureStdout();
        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Observing});
        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Calculating});
        kasumi::application::SyncCompleted empty_summary{};
        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Calculating,
            .summary = empty_summary});
        EXPECT_EQ(kasumi::cli::present(response(
                      empty_summary, kasumi::application::Operation::Sync)),
                  0);

        const auto output = testing::internal::GetCapturedStdout();
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
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::Portuguese);
    {
        testing::internal::CaptureStdout();
        kasumi::application::SyncCompleted summary{
            .total = 4,
            .uploaded = 1,
            .downloaded = 0,
            .removed = 1,
            .renamed = 0,
            .created_dirs = 1,
            .removed_dirs = 1,
            .published = false,
        };
        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Calculating,
            .summary = summary,
            .total_items = 4});
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("4 alterações | ↑ 1 | - 1 | + 1 dir | - 1 dir"),
                  std::string::npos);
    }

    {
        testing::internal::CaptureStdout();
        kasumi::application::SyncCompleted single{
            .total = 1,
            .uploaded = 1,
        };
        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Calculating,
            .summary = single,
            .total_items = 1});
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("1 alteração | ↑ 1"), std::string::npos);
    }

    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
    {
        testing::internal::CaptureStdout();
        kasumi::application::SyncCompleted multiple_dirs{
            .total = 4,
            .created_dirs = 2,
            .removed_dirs = 2,
        };
        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Calculating,
            .summary = multiple_dirs,
            .total_items = 4});
        const auto output = testing::internal::GetCapturedStdout();
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

TEST(CliPresenterTest, FormatsDurationsInMsSecondsAndMinutes) {
    using kasumi::cli::format_duration;
    EXPECT_EQ(format_duration(std::chrono::milliseconds(0)), "0 ms");
    EXPECT_EQ(format_duration(std::chrono::milliseconds(320)), "320 ms");
    EXPECT_EQ(format_duration(std::chrono::milliseconds(999)), "999 ms");
    EXPECT_EQ(format_duration(std::chrono::milliseconds(4800)), "4.8 s");
    EXPECT_EQ(format_duration(std::chrono::milliseconds(5000)), "5 s");
    EXPECT_EQ(format_duration(std::chrono::seconds(72)), "1 min 12 s");
    EXPECT_EQ(format_duration(std::chrono::seconds(60)), "1 min");
    EXPECT_EQ(format_duration(std::chrono::seconds(125)), "2 min 5 s");
    EXPECT_EQ(format_duration(std::chrono::seconds(3665)), "1 h 1 min 5 s");
}

TEST(CliPresenterTest, PresentsCancellationAsWarningWithExitCode130) {
    // Portuguese
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::Portuguese);
    {
        testing::internal::CaptureStdout();
        const int code = kasumi::cli::present_cancellation(
            kasumi::application::Operation::Sync);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_EQ(code, 130);
        EXPECT_NE(output.find("[AVISO]"), std::string::npos);
        EXPECT_NE(output.find("Sincronização cancelada pelo usuário."),
                  std::string::npos);
        EXPECT_EQ(output.find("[ERRO]"), std::string::npos);
        EXPECT_EQ(output.find("Sincronização finalizada com falhas"),
                  std::string::npos);
    }

    // English
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
    {
        testing::internal::CaptureStdout();
        const int code = kasumi::cli::present_cancellation(
            kasumi::application::Operation::Sync);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_EQ(code, 130);
        EXPECT_NE(output.find("[WARNING]"), std::string::npos);
        EXPECT_NE(output.find("Synchronization cancelled by user."),
                  std::string::npos);
        EXPECT_EQ(output.find("[ERROR]"), std::string::npos);
    }

    // Automatic cancellation recognition via platform::cancellation
    kasumi::platform::cancellation::request();
    {
        testing::internal::CaptureStdout();
        const kasumi::application::Error error{
            .operation = kasumi::application::Operation::Sync,
            .code = kasumi::application::ErrorCode::SynchronizationFailure,
            .detail = "operation cancelled by user"};
        const int code = kasumi::cli::present(error);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_EQ(code, 130);
        EXPECT_NE(output.find("[WARNING]"), std::string::npos);
        EXPECT_NE(output.find("Synchronization cancelled by user."),
                  std::string::npos);
        EXPECT_EQ(output.find("[ERROR]"), std::string::npos);
    }
    kasumi::platform::cancellation::reset();
}

TEST(CliPresenterTest, PresentsErrorsWithStageContextInPortugueseAndEnglish) {
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::Portuguese);
    {
        testing::internal::CaptureStdout();
        const kasumi::application::Error error{
            .operation = kasumi::application::Operation::Sync,
            .code = kasumi::application::ErrorCode::PlanFailure,
            .detail = "conexão recusada",
            .stage = kasumi::application::SyncStage::Observing};
        EXPECT_EQ(kasumi::cli::present(error), 1);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha durante a observação."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: conexão recusada"), std::string::npos);
    }

    {
        testing::internal::CaptureStdout();
        const kasumi::application::Error error{
            .operation = kasumi::application::Operation::Sync,
            .code = kasumi::application::ErrorCode::PlanFailure,
            .detail = "conflito irrecuperável",
            .stage = kasumi::application::SyncStage::Calculating};
        EXPECT_EQ(kasumi::cli::present(error), 1);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha ao calcular alterações."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: conflito irrecuperável"),
                  std::string::npos);
    }

    {
        testing::internal::CaptureStdout();
        const kasumi::application::Error error{
            .operation = kasumi::application::Operation::Sync,
            .code = kasumi::application::ErrorCode::SynchronizationFailure,
            .detail = "disco cheio",
            .stage = kasumi::application::SyncStage::Applying};
        EXPECT_EQ(kasumi::cli::present(error), 1);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha ao aplicar alterações."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: disco cheio"), std::string::npos);
    }

    {
        testing::internal::CaptureStdout();
        const kasumi::application::Error error{
            .operation = kasumi::application::Operation::Sync,
            .code = kasumi::application::ErrorCode::SynchronizationFailure,
            .detail = "CommitUploaded falhou",
            .stage = kasumi::application::SyncStage::Publishing};
        EXPECT_EQ(kasumi::cli::present(error), 1);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha durante a publicação."),
                  std::string::npos);
        // Internal state name CommitUploaded sanitized
        EXPECT_EQ(output.find("CommitUploaded"), std::string::npos);
        EXPECT_NE(output.find("Motivo: commit publicado falhou"),
                  std::string::npos);
    }

    {
        testing::internal::CaptureStdout();
        const kasumi::application::Error error{
            .operation = kasumi::application::Operation::Sync,
            .code = kasumi::application::ErrorCode::SynchronizationFailure,
            .detail = "falha de liberação",
            .stage = kasumi::application::SyncStage::Finalizing};
        EXPECT_EQ(kasumi::cli::present(error), 1);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha ao finalizar a sincronização."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: falha de liberação"), std::string::npos);
    }

    // English
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
    {
        testing::internal::CaptureStdout();
        const kasumi::application::Error error{
            .operation = kasumi::application::Operation::Sync,
            .code = kasumi::application::ErrorCode::SynchronizationFailure,
            .detail = "network timeout",
            .stage = kasumi::application::SyncStage::Publishing};
        EXPECT_EQ(kasumi::cli::present(error), 1);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[ERROR]"), std::string::npos);
        EXPECT_NE(output.find("Failure during publication."),
                  std::string::npos);
        EXPECT_NE(output.find("Reason: network timeout"), std::string::npos);
    }
    {
        testing::internal::CaptureStdout();
        const kasumi::application::Error error{
            .operation = kasumi::application::Operation::Sync,
            .code = kasumi::application::ErrorCode::SynchronizationFailure,
            .detail = "CommitUploaded failed",
            .stage = kasumi::application::SyncStage::Publishing};
        EXPECT_EQ(kasumi::cli::present(error), 1);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[ERROR]"), std::string::npos);
        EXPECT_NE(output.find("Failure during publication."),
                  std::string::npos);
        EXPECT_EQ(output.find("CommitUploaded"), std::string::npos);
        EXPECT_NE(output.find("Reason: published commit failed"),
                  std::string::npos);
    }
}

TEST(CliPresenterTest,
     PresentsSyncSummaryWithFormattedSizesAndCompletionDuration) {
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::Portuguese);
    {
        testing::internal::CaptureStdout();
        kasumi::application::SyncCompleted summary{
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

        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Calculating,
            .summary = summary,
            .total_items = 137});
        EXPECT_EQ(kasumi::cli::present(
                      response(summary, kasumi::application::Operation::Sync)),
                  0);

        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find(
                      "137 alterações | ↑ 92 (1.42 GB) | ↓ 31 (284 MB) | - 14"),
                  std::string::npos);
        EXPECT_NE(output.find("[OK]"), std::string::npos);
        EXPECT_NE(output.find("Sincronização concluída em 4.8 s."),
                  std::string::npos);
    }

    // English
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
    {
        testing::internal::CaptureStdout();
        kasumi::application::SyncCompleted summary{
            .total = 137,
            .uploaded = 92,
            .downloaded = 31,
            .removed = 14,
            .upload_bytes = 1524713390,
            .download_bytes = 297795584,
            .published = true,
            .duration = std::chrono::milliseconds(4800),
        };

        kasumi::cli::present(kasumi::application::SyncProgress{
            .stage = kasumi::application::SyncStage::Calculating,
            .summary = summary,
            .total_items = 137});
        EXPECT_EQ(kasumi::cli::present(
                      response(summary, kasumi::application::Operation::Sync)),
                  0);

        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(
            output.find("137 changes | ↑ 92 (1.42 GB) | ↓ 31 (284 MB) | - 14"),
            std::string::npos);
        EXPECT_NE(output.find("[OK]"), std::string::npos);
        EXPECT_NE(output.find("Synchronization completed in 4.8 s."),
                  std::string::npos);
    }
}

TEST(CliPresenterTest, PresentsPlanProgressStagesInPortugueseAndEnglish) {
    // Portuguese
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::Portuguese);
    {
        testing::internal::CaptureStdout();
        kasumi::cli::present(
            kasumi::application::SyncProgress{
                .stage = kasumi::application::SyncStage::Observing},
            kasumi::application::Operation::Preview);
        kasumi::cli::present(
            kasumi::application::SyncProgress{
                .stage = kasumi::application::SyncStage::Calculating},
            kasumi::application::Operation::Preview);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[1/2] Observando estado local e remoto..."),
                  std::string::npos);
        EXPECT_NE(output.find("[2/2] Calculando alterações..."),
                  std::string::npos);
        EXPECT_EQ(output.find("[1/5]"), std::string::npos);
    }
    {
        testing::internal::CaptureStdout();
        kasumi::cli::present(
            kasumi::application::SyncProgress{
                .stage = kasumi::application::SyncStage::Observing},
            kasumi::application::Operation::Status);
        kasumi::cli::present(
            kasumi::application::SyncProgress{
                .stage = kasumi::application::SyncStage::Calculating},
            kasumi::application::Operation::Status);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[1/2] Observando estado local e remoto..."),
                  std::string::npos);
        EXPECT_NE(output.find("[2/2] Calculando alterações..."),
                  std::string::npos);
        EXPECT_EQ(output.find("[1/5]"), std::string::npos);
    }

    // English
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
    {
        testing::internal::CaptureStdout();
        kasumi::cli::present(
            kasumi::application::SyncProgress{
                .stage = kasumi::application::SyncStage::Observing},
            kasumi::application::Operation::Preview);
        kasumi::cli::present(
            kasumi::application::SyncProgress{
                .stage = kasumi::application::SyncStage::Calculating},
            kasumi::application::Operation::Preview);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[1/2] Observing local and remote state..."),
                  std::string::npos);
        EXPECT_NE(output.find("[2/2] Calculating changes..."),
                  std::string::npos);
        EXPECT_EQ(output.find("[1/5]"), std::string::npos);
    }
}

TEST(CliPresenterTest, PresentsPlanErrorsWithStageContext) {
    const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
    {
        testing::internal::CaptureStdout();
        const kasumi::application::Error error{
            .operation = kasumi::application::Operation::Status,
            .code = kasumi::application::ErrorCode::PlanFailure,
            .detail = "falha na observação local",
            .stage = kasumi::application::SyncStage::Observing};
        EXPECT_EQ(kasumi::cli::present(error), 1);
        const auto output = testing::internal::GetCapturedStdout();
        EXPECT_NE(output.find("[ERRO]"), std::string::npos);
        EXPECT_NE(output.find("Falha durante a observação."),
                  std::string::npos);
        EXPECT_NE(output.find("Motivo: falha na observação local"),
                  std::string::npos);
    }
    {
        testing::internal::CaptureStdout();
        const kasumi::application::Error error{
            .operation = kasumi::application::Operation::Preview,
            .code = kasumi::application::ErrorCode::PlanFailure,
            .detail = "conflito irrecuperável",
            .stage = kasumi::application::SyncStage::Calculating};
        EXPECT_EQ(kasumi::cli::present(error), 1);
        const auto output = testing::internal::GetCapturedStdout();
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
        const ScopedLanguage lang{kasumi::cli::i18n::Language::Portuguese};
        testing::internal::CaptureStdout();
        EXPECT_EQ(kasumi::cli::present(response(report)), 0);
        const auto output = testing::internal::GetCapturedStdout();

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
        const ScopedLanguage lang{kasumi::cli::i18n::Language::English};
        testing::internal::CaptureStdout();
        EXPECT_EQ(kasumi::cli::present(response(report)), 0);
        const auto output = testing::internal::GetCapturedStdout();

        EXPECT_NE(output.find("... (5 more items) ..."), std::string::npos);
    }
}

TEST(CliPresenterTest, PresentsPlanReportWithoutTruncationWhenFullFlagIsTrue) {
    PlanReport report;
    for (int i = 0; i < 15; ++i) {
        report.items.push_back(
            {PlanAction::Upload, "file_" + std::to_string(i), {}, 10});
    }

    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response(report), true), 0);
    const auto output = testing::internal::GetCapturedStdout();

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

    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response(report), false), 0);
    const auto output = testing::internal::GetCapturedStdout();

    for (int i = 0; i < 10; ++i) {
        EXPECT_NE(output.find("file_" + std::to_string(i)), std::string::npos);
    }
    EXPECT_EQ(output.find("..."), std::string::npos);
}

} // namespace
