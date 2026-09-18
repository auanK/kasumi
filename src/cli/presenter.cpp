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
        const auto label = commit.logical_head ? "HEAD"
                           : commit.ancestral_marked
                               ? i18n::tr(i18n::Key::LabelAncestralMarker)
                               : i18n::tr(i18n::Key::LabelAncestral);
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
    i18n::println(i18n::Key::FieldHistory,
                  report.history_present
                      ? i18n::tr(i18n::Key::RemoteSummaryHistoryPresent)
                      : i18n::tr(i18n::Key::RemoteSummaryHistoryAbsent));
    i18n::println(i18n::Key::FieldHeight, report.observed_height);
    i18n::println(i18n::Key::FieldReachableCommits,
                  report.reachable_commit_count);
    i18n::println(i18n::Key::FieldLogicalHeads, report.logical_head_count);
    i18n::println(i18n::Key::FieldConflicts, yes_no(report.has_conflicts));
    i18n::println(i18n::Key::FieldMissingContents,
                  report.missing_content_count);
    i18n::println(i18n::Key::FieldOrphanContents, report.orphan_content_count);
    i18n::println(i18n::Key::FieldActiveWriters, report.active_writer_count);
    return 0;
}

int present_remote_stat(const application::RemoteStatReport& report) {
    std::println("{}", i18n::tr(i18n::Key::RemoteStatHeader));
    std::println("{}", i18n::tr(i18n::Key::RemoteStatView));
    i18n::println(i18n::Key::FieldHeight, report.observed_height);
    i18n::println(i18n::Key::FieldConflicts, yes_no(report.has_conflicts));
    i18n::println(i18n::Key::FieldPath, report.path);
    i18n::println(i18n::Key::FieldType,
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
    std::println("{}", i18n::tr(i18n::Key::RemoteCommitHeader));
    i18n::println(i18n::Key::FieldCommit, commit.commit_id);
    i18n::println(i18n::Key::FieldHeight, commit.height);
    i18n::println(i18n::Key::FieldCreatedAt, commit.created_at);
    i18n::println(i18n::Key::FieldLogicalHead, yes_no(commit.logical_head));
    i18n::println(i18n::Key::FieldPhysicalMarker,
                  yes_no(commit.physically_marked));
    i18n::println(i18n::Key::FieldAncestralMarker,
                  yes_no(commit.ancestral_marked));
    i18n::println(i18n::Key::FieldRoot, commit.root_hash);
    i18n::println(i18n::Key::FieldEntries, commit.entry_count);
    i18n::println(i18n::Key::FieldSize, format_size(commit.total_bytes));
    i18n::println(i18n::Key::FieldParentsCount, commit.parent_ids.size());
    for (const auto& parent : commit.parent_ids) {
        std::println("    {}", parent);
    }
    i18n::println(i18n::Key::FieldPhysicalVariants, report.variants.size());
    for (std::size_t index = 0; index < report.variants.size(); ++index) {
        const auto& variant = report.variants[index];
        std::println("\n  [{}]", index + 1);
        i18n::println(i18n::Key::FieldCiphertext, variant.ciphertext_id);
        i18n::println(i18n::Key::FieldObject, variant.object_identifier);
        i18n::println(i18n::Key::FieldState, variant_state(variant.state));
    }
    return 0;
}

int present_remote_file(const application::RemoteFileReport& report) {
    std::println("{}", i18n::tr(i18n::Key::RemoteFileSavedHeader));
    i18n::println(i18n::Key::FieldPath, report.path);
    i18n::println(i18n::Key::FieldDestination, report.destination_path);
    i18n::println(i18n::Key::FieldLogicalHash, report.logical_hash);
    i18n::println(i18n::Key::FieldSize, format_size(report.size));
    return 0;
}

void present_epoch_info(const application::RemoteEpochInfo& epoch) {
    i18n::println(i18n::Key::FieldSequence, epoch.sequence);
    i18n::println(i18n::Key::FieldEpochId, epoch.epoch_id);
    i18n::println(i18n::Key::FieldVaultId, epoch.vault_id);
    i18n::println(i18n::Key::FieldIssuedAt, epoch.issued_at);
    i18n::println(i18n::Key::FieldMinRetention,
                  epoch.min_history_depth,
                  epoch.min_history_age_hours);
    i18n::println(i18n::Key::FieldPreviousEpoch,
                  epoch.previous_epoch_id.empty() ? "-"
                                                  : epoch.previous_epoch_id);
    i18n::println(i18n::Key::FieldNextEpoch,
                  epoch.next_epoch_id.empty() ? "-" : epoch.next_epoch_id);
    i18n::println(i18n::Key::FieldAnchors, epoch.anchors.size());
    for (const auto& anchor : epoch.anchors) {
        std::println("    {}",
                     i18n::format(i18n::Key::FieldAnchorItem,
                                  anchor.commit_id,
                                  anchor.height));
    }
}

int present_remote_epochs(const application::RemoteEpochsReport& report) {
    i18n::println(i18n::Key::RemoteEpochsHeader, report.epochs.size());
    for (std::size_t index = 0; index < report.epochs.size(); ++index) {
        std::println("\n[{}]", index + 1);
        present_epoch_info(report.epochs[index]);
    }
    return 0;
}

int present_remote_epoch(const application::RemoteEpochReport& report) {
    std::println("{}", i18n::tr(i18n::Key::RemoteEpochDetailHeader));
    present_epoch_info(report.epoch);
    return 0;
}

std::string_view content_state(application::RemoteContentState state) {
    switch (state) {
        case application::RemoteContentState::Present:
            return i18n::tr(i18n::Key::ContentStatePresent);
        case application::RemoteContentState::Missing:
            return i18n::tr(i18n::Key::ContentStateMissing);
        case application::RemoteContentState::Orphan:
            return i18n::tr(i18n::Key::ContentStateOrphan);
        case application::RemoteContentState::Valid:
            return i18n::tr(i18n::Key::ContentStateValid);
        case application::RemoteContentState::Invalid:
            return i18n::tr(i18n::Key::ContentStateInvalid);
    }
    return i18n::tr(i18n::Key::ContentStateUnknown);
}

void present_content_info(const application::RemoteContentInfo& content) {
    i18n::println(i18n::Key::FieldContentId, content.content_id);
    i18n::println(i18n::Key::FieldState, content_state(content.state));
    i18n::println(i18n::Key::FieldReferenced, yes_no(content.referenced));
    i18n::println(i18n::Key::FieldPhysicallyPresent,
                  yes_no(content.physically_present));
    i18n::println(i18n::Key::FieldCurrentTree, yes_no(content.current_tree));
    i18n::println(i18n::Key::FieldLogicalHash,
                  content.logical_hash.empty() ? "-" : content.logical_hash);
    i18n::println(i18n::Key::FieldLogicalSize, content.size);
    i18n::println(i18n::Key::FieldPathsCount, content.paths.size());
    for (const auto& path : content.paths) {
        std::println("    {}", path);
    }
}

int present_remote_contents(const application::RemoteContentsReport& report) {
    std::println("{}",
                 i18n::format(i18n::Key::RemoteContentsHeader,
                              report.audited
                                  ? i18n::tr(i18n::Key::RemoteContentsDeepAudit)
                                  : ""));
    i18n::println(i18n::Key::FieldReferenced, report.referenced_count);
    i18n::println(i18n::Key::FieldPhysicalCount, report.physical_count);
    i18n::println(i18n::Key::FieldMissingCount, report.missing_count);
    i18n::println(i18n::Key::FieldOrphanCount, report.orphan_count);
    if (report.audited) {
        i18n::println(i18n::Key::FieldValidCount, report.valid_count);
        i18n::println(i18n::Key::FieldInvalidCount, report.invalid_count);
    }
    for (std::size_t index = 0; index < report.contents.size(); ++index) {
        std::println("\n[{}]", index + 1);
        present_content_info(report.contents[index]);
    }
    return 0;
}

int present_remote_content(const application::RemoteContentReport& report) {
    std::println("{}", i18n::tr(i18n::Key::RemoteContentHeader));
    present_content_info(report.content);
    return 0;
}

std::string_view marker_state(application::RemoteMarkerState state) {
    switch (state) {
        case application::RemoteMarkerState::LogicalHead:
            return i18n::tr(i18n::Key::MarkerStateLogicalHead);
        case application::RemoteMarkerState::Ancestral:
            return i18n::tr(i18n::Key::MarkerStateAncestral);
        case application::RemoteMarkerState::InvalidPath:
            return i18n::tr(i18n::Key::MarkerStateInvalidPath);
        case application::RemoteMarkerState::Missing:
            return i18n::tr(i18n::Key::MarkerStateMissing);
        case application::RemoteMarkerState::InvalidMarker:
            return i18n::tr(i18n::Key::MarkerStateInvalidMarker);
        case application::RemoteMarkerState::MissingCommit:
            return i18n::tr(i18n::Key::MarkerStateMissingCommit);
        case application::RemoteMarkerState::InvalidCiphertext:
            return i18n::tr(i18n::Key::MarkerStateInvalidCiphertext);
        case application::RemoteMarkerState::InvalidCommit:
            return i18n::tr(i18n::Key::MarkerStateInvalidCommit);
    }
    return i18n::tr(i18n::Key::MarkerStateInvalid);
}

int present_remote_markers(const application::RemoteMarkersReport& report) {
    i18n::println(i18n::Key::RemoteMarkersHeader, report.markers.size());
    i18n::println(i18n::Key::FieldLogicalHeads, report.logical_count);
    i18n::println(i18n::Key::FieldAncestralsCount, report.ancestral_count);
    i18n::println(i18n::Key::FieldInvalidCount, report.invalid_count);
    for (std::size_t index = 0; index < report.markers.size(); ++index) {
        const auto& marker = report.markers[index];
        std::println("\n[{}]", index + 1);
        i18n::println(i18n::Key::FieldObject, marker.object_identifier);
        i18n::println(i18n::Key::FieldCommit,
                      marker.commit_id.empty() ? "-" : marker.commit_id);
        i18n::println(i18n::Key::FieldCiphertext,
                      marker.ciphertext_id.empty() ? "-"
                                                   : marker.ciphertext_id);
        i18n::println(i18n::Key::FieldState, marker_state(marker.state));
    }
    return 0;
}

std::string_view object_category(application::RemoteObjectCategory category) {
    switch (category) {
        case application::RemoteObjectCategory::Content:
            return i18n::tr(i18n::Key::ObjectCategoryContent);
        case application::RemoteObjectCategory::CommitVariant:
            return i18n::tr(i18n::Key::ObjectCategoryCommitVariant);
        case application::RemoteObjectCategory::HeadMarker:
            return i18n::tr(i18n::Key::ObjectCategoryHeadMarker);
        case application::RemoteObjectCategory::Epoch:
            return i18n::tr(i18n::Key::ObjectCategoryEpoch);
        case application::RemoteObjectCategory::Writer:
            return i18n::tr(i18n::Key::ObjectCategoryWriter);
        case application::RemoteObjectCategory::Barrier:
            return i18n::tr(i18n::Key::ObjectCategoryBarrier);
        case application::RemoteObjectCategory::Quarantine:
            return i18n::tr(i18n::Key::ObjectCategoryQuarantine);
        case application::RemoteObjectCategory::RetentionMetadata:
            return i18n::tr(i18n::Key::ObjectCategoryRetentionMetadata);
        case application::RemoteObjectCategory::Protocol:
            return i18n::tr(i18n::Key::ObjectCategoryProtocol);
        case application::RemoteObjectCategory::Unknown:
            return i18n::tr(i18n::Key::ObjectCategoryUnknown);
    }
    return i18n::tr(i18n::Key::ObjectCategoryUnknown);
}

int present_remote_objects(const application::RemoteObjectsReport& report) {
    i18n::println(i18n::Key::RemoteObjectsHeader, report.objects.size());
    i18n::println(i18n::Key::FieldUnknownOrInvalid, report.unknown_count);
    for (std::size_t index = 0; index < report.objects.size(); ++index) {
        const auto& object = report.objects[index];
        std::println("\n[{}]", index + 1);
        i18n::println(i18n::Key::FieldIdentifier, object.identifier);
        i18n::println(i18n::Key::FieldCategory,
                      object_category(object.category));
        i18n::println(i18n::Key::FieldStructure,
                      object.structurally_valid
                          ? i18n::tr(i18n::Key::FieldStructureValid)
                          : i18n::tr(i18n::Key::FieldStructureInvalid));
        i18n::println(i18n::Key::FieldRelation, object.relation);
    }
    return 0;
}

std::string_view orphan_kind(application::RemoteOrphanKind kind) {
    switch (kind) {
        case application::RemoteOrphanKind::Commit:
            return i18n::tr(i18n::Key::OrphanKindCommit);
        case application::RemoteOrphanKind::CommitVariant:
            return i18n::tr(i18n::Key::OrphanKindCommitVariant);
        case application::RemoteOrphanKind::RedundantVariant:
            return i18n::tr(i18n::Key::OrphanKindRedundantVariant);
        case application::RemoteOrphanKind::InvalidVariant:
            return i18n::tr(i18n::Key::OrphanKindInvalidVariant);
        case application::RemoteOrphanKind::Content:
            return i18n::tr(i18n::Key::OrphanKindContent);
        case application::RemoteOrphanKind::ProtectedEpoch:
            return i18n::tr(i18n::Key::OrphanKindProtectedEpoch);
        case application::RemoteOrphanKind::Unknown:
            return i18n::tr(i18n::Key::OrphanKindUnknown);
    }
    return i18n::tr(i18n::Key::OrphanKindUnknown);
}

int present_remote_orphans(const application::RemoteOrphansReport& report) {
    i18n::println(i18n::Key::RemoteOrphansHeader, report.objects.size());
    std::println("{}", i18n::tr(i18n::Key::RemoteOrphansReadOnlyHint));
    for (std::size_t index = 0; index < report.objects.size(); ++index) {
        const auto& object = report.objects[index];
        std::println("\n[{}]", index + 1);
        i18n::println(i18n::Key::FieldIdentifier, object.identifier);
        i18n::println(i18n::Key::FieldClassification, orphan_kind(object.kind));
        i18n::println(i18n::Key::FieldStructuralCandidate,
                      yes_no(object.removal_candidate));
    }
    return 0;
}

int present_remote_quarantine(
    const application::RemoteQuarantineReport& report) {
    i18n::println(i18n::Key::RemoteQuarantineHeader, report.entries.size());
    std::println("{}", i18n::tr(i18n::Key::RemoteQuarantineReadOnlyHint));
    for (std::size_t index = 0; index < report.entries.size(); ++index) {
        const auto& entry = report.entries[index];
        std::println("\n[{}]", index + 1);
        i18n::println(i18n::Key::FieldOriginal, entry.original_identifier);
        i18n::println(i18n::Key::FieldQuarantine, entry.quarantine_identifier);
        i18n::println(i18n::Key::FieldMetadata, entry.metadata_identifier);
        i18n::println(i18n::Key::FieldCategory, entry.category);
        i18n::println(i18n::Key::FieldMetadataAuthenticated,
                      yes_no(entry.metadata_authenticated));
        i18n::println(i18n::Key::FieldEnqueued,
                      entry.metadata_authenticated
                          ? std::to_string(entry.quarantined_at)
                          : "-");
        i18n::println(i18n::Key::FieldRetentionElapsed,
                      yes_no(entry.retention_elapsed));
    }
    return 0;
}

int present_remote_writers(const application::RemoteWritersReport& report) {
    i18n::println(i18n::Key::RemoteWritersHeader, report.writers.size());
    i18n::println(i18n::Key::FieldBarrier,
                  report.barrier_present ? i18n::tr(i18n::Key::FieldPresent)
                                         : i18n::tr(i18n::Key::FieldAbsent));
    i18n::println(i18n::Key::FieldMaintenanceBlocked,
                  yes_no(report.maintenance_blocked));
    i18n::println(i18n::Key::FieldProtocolConsistent,
                  yes_no(report.protocol_consistent));
    for (std::size_t index = 0; index < report.writers.size(); ++index) {
        const auto& writer = report.writers[index];
        std::println("\n[{}]", index + 1);
        i18n::println(i18n::Key::FieldIdentifier, writer.identifier);
        i18n::println(i18n::Key::FieldState,
                      writer.state == application::RemoteWriterState::Invalid
                          ? i18n::tr(i18n::Key::WriterStateInvalid)
                          : i18n::tr(i18n::Key::WriterStateIndeterminate));
    }
    return 0;
}

std::string_view health_state(application::RemoteHealthState state) {
    switch (state) {
        case application::RemoteHealthState::Healthy:
            return i18n::tr(i18n::Key::HealthStateHealthy);
        case application::RemoteHealthState::Degraded:
            return i18n::tr(i18n::Key::HealthStateDegraded);
        case application::RemoteHealthState::Critical:
            return i18n::tr(i18n::Key::HealthStateCritical);
    }
    return i18n::tr(i18n::Key::HealthStateCritical);
}

int present_remote_health(const application::RemoteHealthReport& report) {
    i18n::println(i18n::Key::RemoteHealthHeader, health_state(report.state));
    i18n::println(i18n::Key::FieldMarkers, report.marker_count);
    i18n::println(i18n::Key::FieldReachableCommits,
                  report.reachable_commit_count);
    i18n::println(i18n::Key::FieldUnreachableObjects, report.orphan_count);
    i18n::println(i18n::Key::FieldMissingContents,
                  report.missing_content_count);
    i18n::println(i18n::Key::FieldInvalidContents,
                  report.invalid_content_count);
    i18n::println(i18n::Key::FieldWriters, report.writer_count);
    i18n::println(i18n::Key::FieldQuarantine, report.quarantine_count);
    i18n::println(i18n::Key::FieldUnknownObjects, report.unknown_object_count);
    i18n::println(i18n::Key::FieldReasons, report.reasons.size());
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
