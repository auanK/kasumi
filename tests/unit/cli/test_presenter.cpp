#include "application/inspection/result.hpp"
#include "cli/i18n.hpp"
#include "cli/presenter.hpp"

#include <gtest/gtest.h>
#include <string>
#include <utility>

namespace {

using namespace kasumi::application;

class CliPresenterTest : public ::testing::Test {
protected:
    void SetUp() override {
        kasumi::cli::i18n::set_language(
            kasumi::cli::i18n::Language::Portuguese);
    }
    void TearDown() override {
        kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
    }
};

Response response(ResponseData data, Operation operation = Operation::Preview) {
    return Response{.operation = operation,
                    .runtime = RuntimeSummary{"local path", "remote:"},
                    .data = std::move(data)};
}

TEST_F(CliPresenterTest, PresentsEmptyAndPopulatedPlansWithTrafficAndRename) {
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

TEST_F(CliPresenterTest, PresentsSuccessfulResponseVariants) {
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

TEST_F(CliPresenterTest, PresentsSynchronizationErrorsWithoutSecrets) {
    const Error error{.operation = Operation::Sync,
                      .code = ErrorCode::SynchronizationFailure,
                      .detail = "falha controlada",
                      .runtime = std::nullopt};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(error), 1);
    const auto output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("falha controlada"), std::string::npos);
}

TEST_F(CliPresenterTest, PresentsRemoteHeadsSemantically) {
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

TEST_F(CliPresenterTest, PresentsRemoteTreeSemantically) {
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

TEST_F(CliPresenterTest, PresentsRemoteCommitsWithoutInternalDetails) {
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

TEST_F(CliPresenterTest, PresentsRemoteTreeSelectionErrorsWithCandidates) {
    const InspectionError multiple{
        .operation = InspectionOperation::RemoteTree,
        .code = InspectionErrorCode::HeadSelectionRequired,
        .detail = "O histórico remoto possui múltiplas heads lógicas.",
        .candidate_ids = {"head-a", "head-b"}};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(multiple), 1);
    const auto multiple_output = testing::internal::GetCapturedStdout();
    EXPECT_NE(multiple_output.find("múltiplas heads"), std::string::npos);
    EXPECT_NE(multiple_output.find("head-a"), std::string::npos);
    EXPECT_NE(multiple_output.find("head-b"), std::string::npos);
    EXPECT_NE(multiple_output.find("--head"), std::string::npos);

    const InspectionError missing{
        .operation = InspectionOperation::RemoteTree,
        .code = InspectionErrorCode::RemoteHeadNotFound,
        .detail = "a head solicitada não está entre as heads lógicas atuais",
        .candidate_ids = {"head-a"}};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(missing), 1);
    const auto missing_output = testing::internal::GetCapturedStdout();
    EXPECT_NE(missing_output.find("não está entre as heads lógicas atuais"),
              std::string::npos);
    EXPECT_NE(missing_output.find("head-a"), std::string::npos);
}

TEST_F(CliPresenterTest, RejectsIncoherentInspectionPayloadWithoutThrowing) {
    const InspectionResponse response{.operation =
                                          InspectionOperation::RemoteTree,
                                      .payload = RemoteHeadsReport{}};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::present(response), 1);
    const auto output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("resposta de inspeção inconsistente"),
              std::string::npos);
}

TEST_F(CliPresenterTest, PresentsRemoteSummarySemantically) {
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

TEST_F(CliPresenterTest, PresentsRemoteStatSemantically) {
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

TEST_F(CliPresenterTest, PresentsRemoteCommitParentsAndVariants) {
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

TEST_F(CliPresenterTest, PresentsAuthenticatedRemoteFileDownload) {
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

TEST_F(CliPresenterTest, PresentsAuthenticatedEpochChainAndLinks) {
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

TEST_F(CliPresenterTest, PresentsContentInventoryAuditAndDetail) {
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

TEST_F(CliPresenterTest, PresentsEveryPhysicalInspectionReportInPortuguese) {
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
                         .relation = "não auditado"}}}});
    EXPECT_NE(objects.find("Namespace físico remoto"), std::string::npos);
    EXPECT_NE(objects.find("desconhecido"), std::string::npos);
    EXPECT_NE(objects.find("não auditado"), std::string::npos);

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
                         .category = "conteúdo",
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

TEST_F(CliPresenterTest, PresentsRemoteLookupErrors) {
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
                      .detail = "não encontrado"}),
                  1);
        EXPECT_NE(testing::internal::GetCapturedStdout().find("não encontrado"),
                  std::string::npos);
    }
}

TEST_F(CliPresenterTest, PresentsOutputsInEnglishWhenConfigured) {
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);

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

} // namespace
