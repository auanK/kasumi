#include "cli/presenter.hpp"

#include "cli/i18n.hpp"
#include "cli/style.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <format>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kasumi::cli {

std::string format_size(std::uint64_t bytes) {
    if (bytes < 1024) {
        return std::format("{} bytes", bytes);
    }
    constexpr std::array<std::string_view, 4> units = {"KB", "MB", "GB", "TB"};
    double val = static_cast<double>(bytes) / 1024.0;
    std::size_t unit_idx = 0;
    while (val >= 1024.0 && unit_idx + 1 < units.size()) {
        val /= 1024.0;
        ++unit_idx;
    }
    if (val >= 1023.995 && unit_idx + 1 < units.size()) {
        val /= 1024.0;
        ++unit_idx;
    }
    std::string s = std::format("{:.2f}", val);
    if (s.find('.') != std::string::npos) {
        while (s.back() == '0') {
            s.pop_back();
        }
        if (s.back() == '.') {
            s.pop_back();
        }
    }
    return std::format("{} {}", s, units[unit_idx]);
}

std::string format_duration(std::chrono::nanoseconds duration) {
    if (duration < std::chrono::nanoseconds::zero()) {
        duration = std::chrono::nanoseconds::zero();
    }
    if (duration < std::chrono::seconds(1)) {
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(duration)
                .count();
        return std::format("{} ms", ms);
    }
    if (duration < std::chrono::minutes(1)) {
        const double s = std::chrono::duration<double>(duration).count();
        std::string s_str = std::format("{:.1f}", s);
        if (s_str.ends_with(".0")) {
            s_str.erase(s_str.size() - 2);
        }
        return std::format("{} s", s_str);
    }
    const auto total_secs =
        std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    const auto mins = total_secs / 60;
    const auto rem_secs = total_secs % 60;
    if (mins >= 60) {
        const auto hours = mins / 60;
        const auto rem_mins = mins % 60;
        if (rem_mins > 0 && rem_secs > 0) {
            return std::format("{} h {} min {} s", hours, rem_mins, rem_secs);
        }
        if (rem_mins > 0) {
            return std::format("{} h {} min", hours, rem_mins);
        }
        if (rem_secs > 0) {
            return std::format("{} h {} s", hours, rem_secs);
        }
        return std::format("{} h", hours);
    }
    if (rem_secs > 0) {
        return std::format("{} min {} s", mins, rem_secs);
    }
    return std::format("{} min", mins);
}

int present_cancellation(application::Operation operation) {
    const auto key = (operation == application::Operation::Sync)
                         ? i18n::Key::SyncCancelledByUser
                         : i18n::Key::OperationCancelledByUser;
    std::println("{}{}{} {}",
                 style::yellow,
                 i18n::tr(i18n::Key::LabelWarning),
                 style::reset,
                 i18n::tr(key));
    return 130;
}

namespace {

void render_plan_report(const application::PlanReport& report,
                        bool full = false) {
    if (report.has_conflicts) {
        std::println("{}", i18n::tr(i18n::Key::SyncConflictsWarning));
        std::println("{}", i18n::tr(i18n::Key::SyncConflictsStatusHint));
    }

    if (report.items.empty()) {
        std::println("{}", i18n::tr(i18n::Key::SyncNothingToDo));
        return;
    }

    i18n::println(i18n::Key::SyncPlanHeader, report.items.size());

    constexpr const char* ACTION_NAMES[] = {"RenameLocal",
                                            "Upload",
                                            "CreateLocalDirectory",
                                            "CreateRemoteDirectory",
                                            "Download",
                                            "DeleteLocal",
                                            "DeleteLocalDirectory",
                                            "DeleteRemote",
                                            "DeleteRemoteDirectory"};

    auto print_item = [&](const application::PlanItem& item) {
        auto idx = static_cast<std::size_t>(item.action);
        if (idx < std::size(ACTION_NAMES)) {
            std::print("  - [{}] {}",
                       ACTION_NAMES[idx],
                       platform::path::to_utf8(item.path));
            if (item.action == application::PlanAction::RenameLocal) {
                std::print(" -> {}",
                           platform::path::to_utf8(item.alternative_path));
            }
            if (item.action == application::PlanAction::Upload ||
                item.action == application::PlanAction::Download) {
                std::print(" ({})", format_size(item.size));
            }
            std::println("");
        }
    };

    constexpr std::size_t HEAD_COUNT = 5;
    constexpr std::size_t TAIL_COUNT = 5;
    constexpr std::size_t THRESHOLD = HEAD_COUNT + TAIL_COUNT;

    if (full || report.items.size() <= THRESHOLD) {
        for (const auto& item : report.items) {
            print_item(item);
        }
    } else {
        for (std::size_t i = 0; i < HEAD_COUNT; ++i) {
            print_item(report.items[i]);
        }
        const auto omitted = report.items.size() - THRESHOLD;
        const auto omitted_key = (omitted == 1)
                                     ? i18n::Key::SyncPlanOmittedSingular
                                     : i18n::Key::SyncPlanOmittedPlural;
        std::println("  ... ({}) ...", i18n::format(omitted_key, omitted));
        for (std::size_t i = report.items.size() - TAIL_COUNT;
             i < report.items.size();
             ++i) {
            print_item(report.items[i]);
        }
    }

    std::println("{}", i18n::tr(i18n::Key::SyncSummaryHeader));
    for (std::size_t i = 0; i < report.action_counts.size(); ++i) {
        if (report.action_counts[i] > 0) {
            if (i < std::size(ACTION_NAMES)) {
                std::println(
                    "  {}: {}", ACTION_NAMES[i], report.action_counts[i]);
            }
        }
    }

    if (report.upload_bytes > 0 || report.download_bytes > 0) {
        std::println("{}", i18n::tr(i18n::Key::SyncEstimatedTraffic));
        if (report.upload_bytes > 0)
            i18n::println(i18n::Key::SyncUpload,
                          format_size(report.upload_bytes));
        if (report.download_bytes > 0)
            i18n::println(i18n::Key::SyncDownload,
                          format_size(report.download_bytes));
    }
}

std::string_view entry_name(std::string_view path) {
    const auto separator = path.rfind('/');
    return separator == std::string_view::npos ? path
                                               : path.substr(separator + 1);
}

std::size_t entry_depth(std::string_view path) {
    return 1 + static_cast<std::size_t>(std::ranges::count(path, '/'));
}

int present_remote_heads(const application::RemoteHeadsReport& report) {
    if (report.heads.empty()) {
        std::println("{}", i18n::tr(i18n::Key::RemoteHeadsNone));
        return 0;
    }

    i18n::println(i18n::Key::RemoteHeadsHeader, report.heads.size());
    for (std::size_t index = 0; index < report.heads.size(); ++index) {
        const auto& head = report.heads[index];
        std::println("\n[{}]", index + 1);
        i18n::println(i18n::Key::FieldCommit, head.commit_id);
        i18n::println(i18n::Key::FieldHeight, head.height);
        i18n::println(i18n::Key::FieldCreatedAt, head.created_at);
        i18n::println(i18n::Key::FieldParents, head.parent_ids.size());
        i18n::println(i18n::Key::FieldFiles, head.file_count);
        i18n::println(i18n::Key::FieldDirectories, head.directory_count);
        i18n::println(i18n::Key::FieldSize, format_size(head.total_bytes));
        i18n::println(i18n::Key::FieldRoot, head.root_hash);
    }
    return 0;
}

int present_remote_tree(const application::RemoteTreeReport& report) {
    if (!report.history_present) {
        std::println("{}", i18n::tr(i18n::Key::RemoteTreeNone));
        return 0;
    }

    i18n::println(i18n::Key::RemoteTreeHead, report.commit_id);
    i18n::println(i18n::Key::RemoteTreeHeight, report.height);
    i18n::println(i18n::Key::RemoteTreeFiles, report.file_count);
    i18n::println(i18n::Key::RemoteTreeDirectories, report.directory_count);
    i18n::println(i18n::Key::RemoteTreeSize, format_size(report.total_bytes));
    std::println("\n/");
    for (const auto& entry : report.entries) {
        const auto indent = std::string(entry_depth(entry.path) * 2, ' ');
        const auto name = entry_name(entry.path);
        if (entry.type == application::RemoteTreeEntryType::Directory) {
            std::println("{}{}/", indent, name);
        } else {
            std::println("{}{}  {}", indent, name, format_size(entry.size));
        }
    }
    return 0;
}

int present_remote_commits(const application::RemoteCommitsReport& report) {
    if (!report.history_present) {
        std::println("{}", i18n::tr(i18n::Key::RemoteCommitsNone));
        return 0;
    }

    i18n::println(i18n::Key::RemoteCommitsHeader, report.commits.size());
    for (std::size_t index = 0; index < report.commits.size(); ++index) {
        const auto& commit = report.commits[index];
        const auto label = commit.logical_head       ? "HEAD"
                           : commit.ancestral_marked ? "MARKER ANCESTRAL"
                                                     : "ANCESTRAL";
        std::println("\n[{}] {}", index + 1, label);
        i18n::println(i18n::Key::FieldCommit, commit.commit_id);
        i18n::println(i18n::Key::FieldHeight, commit.height);
        i18n::println(i18n::Key::FieldCreatedAt, commit.created_at);
        i18n::println(i18n::Key::FieldParents, commit.parent_ids.size());
        i18n::println(i18n::Key::FieldEntries, commit.entry_count);
        i18n::println(i18n::Key::FieldSize, format_size(commit.total_bytes));
    }
    return 0;
}

std::string_view yes_no(bool value) {
    return value ? i18n::tr(i18n::Key::LabelYes) : i18n::tr(i18n::Key::LabelNo);
}

int present_remote_summary(const application::RemoteSummaryReport& report) {
    std::println("{}", i18n::tr(i18n::Key::RemoteSummaryHeader));
    std::println("  Histórico: {}",
                 report.history_present
                     ? i18n::tr(i18n::Key::RemoteSummaryHistoryPresent)
                     : i18n::tr(i18n::Key::RemoteSummaryHistoryAbsent));
    i18n::println(i18n::Key::FieldHeight, report.observed_height);
    std::println("  Commits alcançáveis: {}", report.reachable_commit_count);
    std::println("  Heads lógicas: {}", report.logical_head_count);
    std::println("  Conflitos: {}", yes_no(report.has_conflicts));
    std::println("  Conteúdos ausentes: {}", report.missing_content_count);
    std::println("  Conteúdos órfãos: {}", report.orphan_content_count);
    std::println("  Writers ativos: {}", report.active_writer_count);
    return 0;
}

int present_remote_stat(const application::RemoteStatReport& report) {
    std::println("{}", i18n::tr(i18n::Key::RemoteStatHeader));
    std::println("{}", i18n::tr(i18n::Key::RemoteStatView));
    i18n::println(i18n::Key::FieldHeight, report.observed_height);
    std::println("  Conflitos: {}", yes_no(report.has_conflicts));
    i18n::println(i18n::Key::FieldPath, report.path);
    std::println("  Tipo: {}",
                 report.type == application::RemoteTreeEntryType::Directory
                     ? i18n::tr(i18n::Key::RemoteStatDirectory)
                     : i18n::tr(i18n::Key::RemoteStatFile));
    i18n::println(i18n::Key::FieldLogicalHash, report.logical_hash);
    i18n::println(i18n::Key::FieldSize, format_size(report.size));
    i18n::println(i18n::Key::FieldModifiedAt,
                  report.modified_at_unix_nanoseconds);
    return 0;
}

std::string_view variant_state(application::RemoteCommitVariantState state) {
    switch (state) {
        case application::RemoteCommitVariantState::Valid:
            return i18n::tr(i18n::Key::VariantValid);
        case application::RemoteCommitVariantState::InvalidCiphertext:
            return i18n::tr(i18n::Key::VariantInvalidCiphertext);
        case application::RemoteCommitVariantState::InvalidCommit:
            return i18n::tr(i18n::Key::VariantInvalidCommit);
    }
    return i18n::tr(i18n::Key::VariantInvalid);
}

int present_remote_commit(const application::RemoteCommitReport& report) {
    const auto& commit = report.commit;
    std::println("Commit remoto");
    std::println("  Commit: {}", commit.commit_id);
    std::println("  Altura: {}", commit.height);
    std::println("  Criado em: {}", commit.created_at);
    std::println("  Head lógica: {}", yes_no(commit.logical_head));
    std::println("  Marker físico: {}", yes_no(commit.physically_marked));
    std::println("  Marker ancestral: {}", yes_no(commit.ancestral_marked));
    std::println("  Raiz: {}", commit.root_hash);
    std::println("  Entradas: {}", commit.entry_count);
    std::println("  Tamanho: {}", format_size(commit.total_bytes));
    std::println("  Pais ({}):", commit.parent_ids.size());
    for (const auto& parent : commit.parent_ids) {
        std::println("    {}", parent);
    }
    std::println("  Variantes físicas ({}):", report.variants.size());
    for (std::size_t index = 0; index < report.variants.size(); ++index) {
        const auto& variant = report.variants[index];
        std::println("\n  [{}]", index + 1);
        std::println("    Ciphertext: {}", variant.ciphertext_id);
        std::println("    Objeto: {}", variant.object_identifier);
        std::println("    Estado: {}", variant_state(variant.state));
    }
    return 0;
}

int present_remote_file(const application::RemoteFileReport& report) {
    std::println("Arquivo remoto salvo");
    std::println("  Caminho: {}", report.path);
    std::println("  Destino: {}", report.destination_path);
    std::println("  Hash lógico: {}", report.logical_hash);
    std::println("  Tamanho: {}", format_size(report.size));
    return 0;
}

void present_epoch_info(const application::RemoteEpochInfo& epoch) {
    std::println("  Sequência: {}", epoch.sequence);
    std::println("  Epoch ID: {}", epoch.epoch_id);
    std::println("  Vault ID: {}", epoch.vault_id);
    std::println("  Emitido em: {}", epoch.issued_at);
    std::println("  Retenção mínima: {} commit(s), {} hora(s)",
                 epoch.min_history_depth,
                 epoch.min_history_age_hours);
    std::println("  Epoch anterior: {}",
                 epoch.previous_epoch_id.empty() ? "-"
                                                 : epoch.previous_epoch_id);
    std::println("  Próximo Epoch: {}",
                 epoch.next_epoch_id.empty() ? "-" : epoch.next_epoch_id);
    std::println("  Âncoras ({}):", epoch.anchors.size());
    for (const auto& anchor : epoch.anchors) {
        std::println("    {} (altura {})", anchor.commit_id, anchor.height);
    }
}

int present_remote_epochs(const application::RemoteEpochsReport& report) {
    std::println("Epochs remotos: {}", report.epochs.size());
    for (std::size_t index = 0; index < report.epochs.size(); ++index) {
        std::println("\n[{}]", index + 1);
        present_epoch_info(report.epochs[index]);
    }
    return 0;
}

int present_remote_epoch(const application::RemoteEpochReport& report) {
    std::println("Epoch remoto");
    present_epoch_info(report.epoch);
    return 0;
}

std::string_view content_state(application::RemoteContentState state) {
    switch (state) {
        case application::RemoteContentState::Present:
            return "presente (não auditado)";
        case application::RemoteContentState::Missing:
            return "ausente";
        case application::RemoteContentState::Orphan:
            return "órfão (não auditado)";
        case application::RemoteContentState::Valid:
            return "válido";
        case application::RemoteContentState::Invalid:
            return "inválido";
    }
    return "desconhecido";
}

void present_content_info(const application::RemoteContentInfo& content) {
    std::println("  Content ID: {}", content.content_id);
    std::println("  Estado: {}", content_state(content.state));
    std::println("  Referenciado: {}", yes_no(content.referenced));
    std::println("  Presente fisicamente: {}",
                 yes_no(content.physically_present));
    std::println("  Na árvore atual: {}", yes_no(content.current_tree));
    std::println("  Hash lógico: {}",
                 content.logical_hash.empty() ? "-" : content.logical_hash);
    std::println("  Tamanho lógico: {} bytes", content.size);
    std::println("  Caminhos ({}):", content.paths.size());
    for (const auto& path : content.paths) {
        std::println("    {}", path);
    }
}

int present_remote_contents(const application::RemoteContentsReport& report) {
    std::println("Conteúdos remotos{}",
                 report.audited ? " — auditoria profunda" : "");
    std::println("  Referenciados: {}", report.referenced_count);
    std::println("  Físicos: {}", report.physical_count);
    std::println("  Ausentes: {}", report.missing_count);
    std::println("  Órfãos: {}", report.orphan_count);
    if (report.audited) {
        std::println("  Válidos: {}", report.valid_count);
        std::println("  Inválidos: {}", report.invalid_count);
    }
    for (std::size_t index = 0; index < report.contents.size(); ++index) {
        std::println("\n[{}]", index + 1);
        present_content_info(report.contents[index]);
    }
    return 0;
}

int present_remote_content(const application::RemoteContentReport& report) {
    std::println("Conteúdo remoto");
    present_content_info(report.content);
    return 0;
}

std::string_view marker_state(application::RemoteMarkerState state) {
    switch (state) {
        case application::RemoteMarkerState::LogicalHead:
            return "head lógica autenticada";
        case application::RemoteMarkerState::Ancestral:
            return "marker ancestral autenticado";
        case application::RemoteMarkerState::InvalidPath:
            return "identificador inválido";
        case application::RemoteMarkerState::Missing:
            return "ausente";
        case application::RemoteMarkerState::InvalidMarker:
            return "marker inválido";
        case application::RemoteMarkerState::MissingCommit:
            return "commit ausente";
        case application::RemoteMarkerState::InvalidCiphertext:
            return "ciphertext inválido";
        case application::RemoteMarkerState::InvalidCommit:
            return "commit inválido";
    }
    return "inválido";
}

int present_remote_markers(const application::RemoteMarkersReport& report) {
    std::println("Markers físicos remotos: {}", report.markers.size());
    std::println("  Heads lógicas: {}", report.logical_count);
    std::println("  Ancestrais: {}", report.ancestral_count);
    std::println("  Inválidos: {}", report.invalid_count);
    for (std::size_t index = 0; index < report.markers.size(); ++index) {
        const auto& marker = report.markers[index];
        std::println("\n[{}]", index + 1);
        std::println("  Objeto: {}", marker.object_identifier);
        std::println("  Commit: {}",
                     marker.commit_id.empty() ? "-" : marker.commit_id);
        std::println("  Ciphertext: {}",
                     marker.ciphertext_id.empty() ? "-" : marker.ciphertext_id);
        std::println("  Estado: {}", marker_state(marker.state));
    }
    return 0;
}

std::string_view object_category(application::RemoteObjectCategory category) {
    switch (category) {
        case application::RemoteObjectCategory::Content:
            return "conteúdo";
        case application::RemoteObjectCategory::CommitVariant:
            return "variante de commit";
        case application::RemoteObjectCategory::HeadMarker:
            return "marker de HEAD";
        case application::RemoteObjectCategory::Epoch:
            return "Epoch";
        case application::RemoteObjectCategory::Writer:
            return "writer";
        case application::RemoteObjectCategory::Barrier:
            return "barrier";
        case application::RemoteObjectCategory::Quarantine:
            return "quarentena";
        case application::RemoteObjectCategory::RetentionMetadata:
            return "metadata de retenção";
        case application::RemoteObjectCategory::Protocol:
            return "protocolo";
        case application::RemoteObjectCategory::Unknown:
            return "desconhecido";
    }
    return "desconhecido";
}

int present_remote_objects(const application::RemoteObjectsReport& report) {
    std::println("Namespace físico remoto: {} objeto(s)",
                 report.objects.size());
    std::println("  Desconhecidos ou inválidos: {}", report.unknown_count);
    for (std::size_t index = 0; index < report.objects.size(); ++index) {
        const auto& object = report.objects[index];
        std::println("\n[{}]", index + 1);
        std::println("  Identificador: {}", object.identifier);
        std::println("  Categoria: {}", object_category(object.category));
        std::println("  Estrutura: {}",
                     object.structurally_valid ? "válida" : "inválida");
        std::println("  Relação: {}", object.relation);
    }
    return 0;
}

std::string_view orphan_kind(application::RemoteOrphanKind kind) {
    switch (kind) {
        case application::RemoteOrphanKind::Commit:
            return "commit lógico órfão";
        case application::RemoteOrphanKind::CommitVariant:
            return "variante órfã";
        case application::RemoteOrphanKind::RedundantVariant:
            return "variante redundante";
        case application::RemoteOrphanKind::InvalidVariant:
            return "variante inválida";
        case application::RemoteOrphanKind::Content:
            return "conteúdo órfão";
        case application::RemoteOrphanKind::ProtectedEpoch:
            return "Epoch histórico protegido";
        case application::RemoteOrphanKind::Unknown:
            return "objeto desconhecido";
    }
    return "objeto desconhecido";
}

int present_remote_orphans(const application::RemoteOrphansReport& report) {
    std::println("Objetos sem alcance: {}", report.objects.size());
    std::println("  Diagnóstico somente-leitura; isto não é um plano de GC.");
    for (std::size_t index = 0; index < report.objects.size(); ++index) {
        const auto& object = report.objects[index];
        std::println("\n[{}]", index + 1);
        std::println("  Identificador: {}", object.identifier);
        std::println("  Classificação: {}", orphan_kind(object.kind));
        std::println("  Candidato estrutural: {}",
                     yes_no(object.removal_candidate));
    }
    return 0;
}

int present_remote_quarantine(
    const application::RemoteQuarantineReport& report) {
    std::println("Quarentena remota: {} objeto(s)", report.entries.size());
    std::println(
        "  Inspeção somente-leitura; nada será restaurado ou purgado.");
    for (std::size_t index = 0; index < report.entries.size(); ++index) {
        const auto& entry = report.entries[index];
        std::println("\n[{}]", index + 1);
        std::println("  Original: {}", entry.original_identifier);
        std::println("  Quarentena: {}", entry.quarantine_identifier);
        std::println("  Metadata: {}", entry.metadata_identifier);
        std::println("  Categoria: {}", entry.category);
        std::println("  Metadata autenticada: {}",
                     yes_no(entry.metadata_authenticated));
        std::println("  Entrada: {}",
                     entry.metadata_authenticated
                         ? std::to_string(entry.quarantined_at)
                         : "-");
        std::println("  Retenção transcorrida: {}",
                     yes_no(entry.retention_elapsed));
    }
    return 0;
}

int present_remote_writers(const application::RemoteWritersReport& report) {
    std::println("Writers remotos: {}", report.writers.size());
    std::println("  Barrier: {}",
                 report.barrier_present ? "presente" : "ausente");
    std::println("  Manutenção bloqueada: {}",
                 yes_no(report.maintenance_blocked));
    std::println("  Protocolo consistente: {}",
                 yes_no(report.protocol_consistent));
    for (std::size_t index = 0; index < report.writers.size(); ++index) {
        const auto& writer = report.writers[index];
        std::println("\n[{}]", index + 1);
        std::println("  Identificador: {}", writer.identifier);
        std::println("  Estado: {}",
                     writer.state == application::RemoteWriterState::Invalid
                         ? "inválido"
                         : "indeterminado; bloqueia enquanto presente");
    }
    return 0;
}

std::string_view health_state(application::RemoteHealthState state) {
    switch (state) {
        case application::RemoteHealthState::Healthy:
            return "saudável";
        case application::RemoteHealthState::Degraded:
            return "degradado";
        case application::RemoteHealthState::Critical:
            return "crítico";
    }
    return "crítico";
}

int present_remote_health(const application::RemoteHealthReport& report) {
    std::println("Saúde remota: {}", health_state(report.state));
    std::println("  Markers: {}", report.marker_count);
    std::println("  Commits alcançáveis: {}", report.reachable_commit_count);
    std::println("  Objetos sem alcance: {}", report.orphan_count);
    std::println("  Conteúdos ausentes: {}", report.missing_content_count);
    std::println("  Conteúdos inválidos: {}", report.invalid_content_count);
    std::println("  Writers: {}", report.writer_count);
    std::println("  Quarentena: {}", report.quarantine_count);
    std::println("  Objetos desconhecidos: {}", report.unknown_object_count);
    std::println("  Razões ({}):", report.reasons.size());
    for (const auto& reason : report.reasons) {
        std::println("    {}", reason);
    }
    return 0;
}

void render_sync_summary(const application::SyncCompleted& summary) {
    if (summary.total == 0) {
        std::println("      {}", i18n::tr(i18n::Key::SyncEverythingInSync));
        std::println();
        return;
    }

    std::vector<std::string> parts;
    if (summary.total == 1) {
        parts.push_back(
            i18n::format(i18n::Key::SyncChangesSingular, summary.total));
    } else {
        parts.push_back(
            i18n::format(i18n::Key::SyncChangesPlural, summary.total));
    }

    if (summary.uploaded > 0) {
        if (summary.upload_bytes > 0) {
            parts.push_back(std::format("↑ {} ({})",
                                        summary.uploaded,
                                        format_size(summary.upload_bytes)));
        } else {
            parts.push_back(std::format("↑ {}", summary.uploaded));
        }
    }
    if (summary.downloaded > 0) {
        if (summary.download_bytes > 0) {
            parts.push_back(std::format("↓ {} ({})",
                                        summary.downloaded,
                                        format_size(summary.download_bytes)));
        } else {
            parts.push_back(std::format("↓ {}", summary.downloaded));
        }
    }
    if (summary.removed > 0) {
        parts.push_back(std::format("- {}", summary.removed));
    }
    if (summary.renamed > 0) {
        parts.push_back(std::format("→ {}", summary.renamed));
    }
    if (summary.created_dirs > 0) {
        parts.push_back(i18n::format(summary.created_dirs == 1
                                         ? i18n::Key::SyncCreatedDirSingular
                                         : i18n::Key::SyncCreatedDirPlural,
                                     summary.created_dirs));
    }
    if (summary.removed_dirs > 0) {
        parts.push_back(i18n::format(summary.removed_dirs == 1
                                         ? i18n::Key::SyncRemovedDirSingular
                                         : i18n::Key::SyncRemovedDirPlural,
                                     summary.removed_dirs));
    }

    std::string line = "      ";
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            line += " | ";
        }
        line += parts[i];
    }
    std::println("{}", line);
    std::println();
}

} // namespace

void present(const application::SyncProgress& progress,
             application::Operation operation) {
    if (operation == application::Operation::Preview ||
        operation == application::Operation::Status) {
        switch (progress.stage) {
            case application::SyncStage::Observing:
                std::println("{}", i18n::tr(i18n::Key::PlanStageObserving));
                break;
            case application::SyncStage::Calculating:
                std::println("{}", i18n::tr(i18n::Key::PlanStageCalculating));
                std::println();
                break;
            default:
                break;
        }
        return;
    }

    switch (progress.stage) {
        case application::SyncStage::Observing:
            std::println("{}", i18n::tr(i18n::Key::SyncStageObserving));
            break;
        case application::SyncStage::Calculating:
            if (!progress.summary) {
                std::println("{}", i18n::tr(i18n::Key::SyncStageCalculating));
            } else {
                render_sync_summary(*progress.summary);
            }
            break;
        case application::SyncStage::Applying:
            std::println("{}", i18n::tr(i18n::Key::SyncStageApplying));
            break;
        case application::SyncStage::Publishing:
            std::println("{}", i18n::tr(i18n::Key::SyncStagePublishing));
            break;
        case application::SyncStage::Finalizing:
            std::println("{}", i18n::tr(i18n::Key::SyncStageFinalizing));
            std::println();
            break;
    }
}

int present(const application::Response& response, bool full) {
    if (const auto* sync =
            std::get_if<application::SyncCompleted>(&response.data)) {
        if (sync->duration.has_value()) {
            std::println("{}{}{} {}",
                         style::green,
                         i18n::tr(i18n::Key::LabelOk),
                         style::reset,
                         i18n::format(i18n::Key::SyncCompletedWithDuration,
                                      format_duration(*sync->duration)));
        } else {
            std::println("{}{}{} {}",
                         style::green,
                         i18n::tr(i18n::Key::LabelOk),
                         style::reset,
                         i18n::tr(i18n::Key::SyncCompleted));
        }
        return 0;
    }
    if (const auto* ptr =
            std::get_if<application::PlanReport>(&response.data)) {
        render_plan_report(*ptr, full);
        if (response.operation == application::Operation::Preview) {
            std::println("{}", i18n::tr(i18n::Key::PreviewCompleted));
        }
        return 0;
    }
    if (std::holds_alternative<application::FsckCompleted>(response.data)) {
        std::println("{}", i18n::tr(i18n::Key::ErrorFsckAuditing));
        std::println("{}{}{} {}",
                     style::green,
                     i18n::tr(i18n::Key::LabelOk),
                     style::reset,
                     i18n::tr(i18n::Key::ErrorFsckClean));
        return 0;
    }
    if (const auto* ptr =
            std::get_if<application::GarbageCollectCompleted>(&response.data)) {
        std::println("{}", i18n::tr(i18n::Key::ErrorGcRunning));
        if (ptr->analysis_only) {
            std::println("{}",
                         i18n::format(i18n::Key::ErrorGcWarning,
                                      ptr->candidate_objects));
            return 0;
        }
        std::println("{}{}{} {}",
                     style::green,
                     i18n::tr(i18n::Key::LabelOk),
                     style::reset,
                     i18n::format(i18n::Key::ErrorGcCompleted,
                                  ptr->candidate_objects,
                                  ptr->quarantined_objects,
                                  ptr->restored_objects,
                                  ptr->purged_objects));
        return 0;
    }
    return 0;
}

int present(const application::InspectionResponse& response) {
    if (response.operation == application::InspectionOperation::RemoteHeads) {
        if (const auto* report = std::get_if<application::RemoteHeadsReport>(
                &response.payload)) {
            return present_remote_heads(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteTree) {
        if (const auto* report =
                std::get_if<application::RemoteTreeReport>(&response.payload)) {
            return present_remote_tree(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteCommits) {
        if (const auto* report = std::get_if<application::RemoteCommitsReport>(
                &response.payload)) {
            return present_remote_commits(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteSummary) {
        if (const auto* report = std::get_if<application::RemoteSummaryReport>(
                &response.payload)) {
            return present_remote_summary(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteStat) {
        if (const auto* report =
                std::get_if<application::RemoteStatReport>(&response.payload)) {
            return present_remote_stat(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteCommit) {
        if (const auto* report = std::get_if<application::RemoteCommitReport>(
                &response.payload)) {
            return present_remote_commit(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteGet) {
        if (const auto* report =
                std::get_if<application::RemoteFileReport>(&response.payload)) {
            return present_remote_file(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteEpochs) {
        if (const auto* report = std::get_if<application::RemoteEpochsReport>(
                &response.payload)) {
            return present_remote_epochs(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteEpoch) {
        if (const auto* report = std::get_if<application::RemoteEpochReport>(
                &response.payload)) {
            return present_remote_epoch(*report);
        }
    } else if (response.operation ==
                   application::InspectionOperation::RemoteContents ||
               response.operation ==
                   application::InspectionOperation::RemoteContentsAudit) {
        if (const auto* report = std::get_if<application::RemoteContentsReport>(
                &response.payload)) {
            return present_remote_contents(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteContent) {
        if (const auto* report = std::get_if<application::RemoteContentReport>(
                &response.payload)) {
            return present_remote_content(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteMarkers) {
        if (const auto* report = std::get_if<application::RemoteMarkersReport>(
                &response.payload)) {
            return present_remote_markers(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteObjects) {
        if (const auto* report = std::get_if<application::RemoteObjectsReport>(
                &response.payload)) {
            return present_remote_objects(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteOrphans) {
        if (const auto* report = std::get_if<application::RemoteOrphansReport>(
                &response.payload)) {
            return present_remote_orphans(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteQuarantine) {
        if (const auto* report =
                std::get_if<application::RemoteQuarantineReport>(
                    &response.payload)) {
            return present_remote_quarantine(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteWriters) {
        if (const auto* report = std::get_if<application::RemoteWritersReport>(
                &response.payload)) {
            return present_remote_writers(*report);
        }
    } else if (response.operation ==
               application::InspectionOperation::RemoteHealth) {
        if (const auto* report = std::get_if<application::RemoteHealthReport>(
                &response.payload)) {
            return present_remote_health(*report);
        }
    }

    std::println("{}{}{} {}",
                 style::red,
                 i18n::tr(i18n::Key::LabelError),
                 style::reset,
                 i18n::tr(i18n::Key::ErrorInconsistentInspection));
    return 1;
}

namespace {

std::string sanitize_error_detail(std::string_view detail) {
    std::string result{detail};
    constexpr std::array<std::pair<std::string_view, std::string_view>, 4>
        tokens_pt = {{{"CommitUploaded", "commit publicado"},
                      {"HeadVerified", "head verificada"},
                      {"EpochPrepared", "epoch preparado"},
                      {"DatabaseCommitted", "estado persistido"}}};
    constexpr std::array<std::pair<std::string_view, std::string_view>, 4>
        tokens_en = {{{"CommitUploaded", "published commit"},
                      {"HeadVerified", "verified head"},
                      {"EpochPrepared", "prepared epoch"},
                      {"DatabaseCommitted", "persisted state"}}};
    const auto& internal_tokens =
        (i18n::current_language() == i18n::Language::Portuguese) ? tokens_pt
                                                                 : tokens_en;
    for (const auto& [token, replacement] : internal_tokens) {
        std::size_t pos = 0;
        while ((pos = result.find(token, pos)) != std::string::npos) {
            result.replace(pos, token.length(), replacement);
            pos += replacement.length();
        }
    }
    return result;
}

} // namespace

int present(const application::Error& error) {
    if (platform::cancellation::requested() ||
        error.detail.find("cancelada pelo usuário") != std::string::npos ||
        error.detail.find("cancelled by user") != std::string::npos) {
        return present_cancellation(error.operation);
    }

    if ((error.operation == application::Operation::Sync ||
         error.operation == application::Operation::Preview ||
         error.operation == application::Operation::Status) &&
        error.stage.has_value()) {
        i18n::Key stage_key = i18n::Key::SyncErrorObserving;
        switch (*error.stage) {
            case application::SyncStage::Observing:
                stage_key = i18n::Key::SyncErrorObserving;
                break;
            case application::SyncStage::Calculating:
                stage_key = i18n::Key::SyncErrorCalculating;
                break;
            case application::SyncStage::Applying:
                stage_key = i18n::Key::SyncErrorApplying;
                break;
            case application::SyncStage::Publishing:
                stage_key = i18n::Key::SyncErrorPublishing;
                break;
            case application::SyncStage::Finalizing:
                stage_key = i18n::Key::SyncErrorFinalizing;
                break;
        }
        std::println("{}{}{} {}",
                     style::red,
                     i18n::tr(i18n::Key::LabelError),
                     style::reset,
                     i18n::tr(stage_key));
        std::println("{}",
                     i18n::format(i18n::Key::SyncErrorReason,
                                  sanitize_error_detail(error.detail)));
        return 1;
    }

    switch (error.code) {
        case application::ErrorCode::InvalidProfile:
        case application::ErrorCode::ProfileNotFound:
        case application::ErrorCode::RuntimeFailure:
        case application::ErrorCode::CredentialsRequired:
        case application::ErrorCode::CredentialFailure:
            std::println("{}{}{} {}",
                         style::red,
                         i18n::tr(i18n::Key::LabelError),
                         style::reset,
                         error.detail);
            break;
        case application::ErrorCode::PlanFailure:
            std::println(
                "{}{}{} {}",
                style::red,
                i18n::tr(i18n::Key::LabelError),
                style::reset,
                i18n::format(i18n::Key::ErrorPlanCalculation, error.detail));
            break;
        case application::ErrorCode::FsckFailure:
            std::println("{}", i18n::tr(i18n::Key::ErrorFsckAuditing));
            std::println(
                "{}{}{} {}",
                style::red,
                i18n::tr(i18n::Key::LabelError),
                style::reset,
                i18n::format(i18n::Key::ErrorFsckFailed, error.detail));
            break;
        case application::ErrorCode::GarbageCollectionFailure:
            std::println("{}", i18n::tr(i18n::Key::ErrorGcRunning));
            std::println(
                "{}{}{} {}",
                style::red,
                i18n::tr(i18n::Key::LabelError),
                style::reset,
                i18n::format(i18n::Key::ErrorGcCancelled, error.detail));
            break;
        case application::ErrorCode::SynchronizationFailure:
            std::println(
                "{}{}{} {}",
                style::red,
                i18n::tr(i18n::Key::LabelError),
                style::reset,
                i18n::format(i18n::Key::ErrorSyncFailed, error.detail));
            break;
    }
    return 1;
}

int present(const application::InspectionError& error) {
    if (error.code == application::InspectionErrorCode::HeadSelectionRequired) {
        std::println("{}{}{} {}",
                     style::red,
                     i18n::tr(i18n::Key::LabelError),
                     style::reset,
                     error.detail);
        std::println("{}", i18n::tr(i18n::Key::ErrorAvailableHeads));
        for (const auto& id : error.candidate_ids) {
            std::println("  {}", id);
        }
        std::println("{}", i18n::tr(i18n::Key::ErrorUseRemoteTreeHead));
        return 1;
    }

    std::println("{}{}{} {}",
                 style::red,
                 i18n::tr(i18n::Key::LabelError),
                 style::reset,
                 error.detail);
    if (error.code == application::InspectionErrorCode::RemoteHeadNotFound &&
        !error.candidate_ids.empty()) {
        std::println("{}", i18n::tr(i18n::Key::ErrorAvailableHeads));
        for (const auto& id : error.candidate_ids) {
            std::println("  {}", id);
        }
    }
    return 1;
}

} // namespace kasumi::cli
