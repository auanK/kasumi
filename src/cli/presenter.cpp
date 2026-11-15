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

template <typename Enum, std::size_t N>
constexpr i18n::Key
enum_key(Enum value,
         const std::array<std::pair<Enum, i18n::Key>, N>& table,
         i18n::Key fallback) noexcept {
    for (const auto& [candidate, key] : table) {
        if (candidate == value) {
            return key;
        }
    }
    return fallback;
}

template <typename Enum, std::size_t N>
std::string_view enum_tr(Enum value,
                         const std::array<std::pair<Enum, i18n::Key>, N>& table,
                         i18n::Key fallback) {
    return i18n::tr(enum_key(value, table, fallback));
}

void print_status_line(std::string_view color,
                       i18n::Key label,
                       std::string_view message) {
    std::println("{}{}{} {}", color, i18n::tr(label), style::reset, message);
}

void print_ok_line(std::string_view message) {
    print_status_line(style::green, i18n::Key::LabelOk, message);
}

void print_error_line(std::string_view message) {
    print_status_line(style::red, i18n::Key::LabelError, message);
}

std::string
format_plural(std::uint64_t count, i18n::Key singular, i18n::Key plural) {
    return count == 1 ? std::string{i18n::tr(singular)}
                      : i18n::format(plural, count);
}

int present_help(std::string_view topic) {
    constexpr std::pair<std::string_view, i18n::Key> topics[]{
        {"sync", i18n::Key::HelpSync},
        {"status", i18n::Key::HelpStatus},
        {"fsck", i18n::Key::HelpFsck},
        {"gc", i18n::Key::HelpGc},
        {"gc remove-writer", i18n::Key::HelpGcRemoveWriter},
        {"gc remove-barrier", i18n::Key::HelpGcRemoveBarrier},
        {"resolve-missing", i18n::Key::HelpResolveMissing},
        {"remote", i18n::Key::HelpRemote},
        {"config", i18n::Key::HelpConfig},
        {"update", i18n::Key::HelpUpdate},
        {"remote heads", i18n::Key::HelpRemoteHeads},
        {"remote tree", i18n::Key::HelpRemoteTree},
        {"remote commits", i18n::Key::HelpRemoteCommits},
        {"remote summary", i18n::Key::HelpRemoteSummary},
        {"remote stat", i18n::Key::HelpRemoteStat},
        {"remote commit", i18n::Key::HelpRemoteCommit},
        {"remote get", i18n::Key::HelpRemoteGet},
        {"remote epochs", i18n::Key::HelpRemoteEpochs},
        {"remote epoch", i18n::Key::HelpRemoteEpoch},
        {"remote contents", i18n::Key::HelpRemoteContents},
        {"remote content", i18n::Key::HelpRemoteContent},
        {"remote markers", i18n::Key::HelpRemoteMarkers},
        {"remote objects", i18n::Key::HelpRemoteObjects},
        {"remote orphans", i18n::Key::HelpRemoteOrphans},
        {"remote writers", i18n::Key::HelpRemoteWriters},
        {"remote health", i18n::Key::HelpRemoteHealth},
    };
    for (const auto& [name, key] : topics) {
        if (name == topic) {
            std::print("{}{}", i18n::tr(key), i18n::tr(i18n::Key::HelpOptions));
            return 0;
        }
    }
    std::print("{}", i18n::tr(i18n::Key::HelpText));
    return 0;
}

int present_parse_error(std::string_view topic) {
    const std::string suffix = topic.empty() ? "" : " " + std::string{topic};
    std::println(stderr,
                 "{} {}",
                 i18n::tr(i18n::Key::LabelError),
                 i18n::format(i18n::Key::ErrorInvalidArguments, suffix));
    return 1;
}

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
    return std::format("{:.3f} s",
                       std::chrono::duration<double>(
                           std::max(duration, std::chrono::nanoseconds::zero()))
                           .count());
}

void present_duration(std::chrono::nanoseconds duration) {
    std::println(
        "{}",
        i18n::format(i18n::Key::OperationDuration, format_duration(duration)));
}

int present_cancellation(application::Operation operation) {
    print_status_line(style::yellow,
                      i18n::Key::LabelWarning,
                      i18n::tr(operation == application::Operation::Sync
                                   ? i18n::Key::SyncCancelledByUser
                                   : i18n::Key::OperationCancelledByUser));
    return 130;
}

namespace {

void render_bounded(const auto& items,
                    bool full,
                    const auto& print_item,
                    const auto& print_omitted) {
    constexpr std::size_t head_count = 5;
    constexpr std::size_t tail_count = 5;
    if (full || items.size() <= head_count + tail_count) {
        for (const auto& item : items) {
            print_item(item);
        }
        return;
    }

    for (std::size_t index = 0; index < head_count; ++index) {
        print_item(items[index]);
    }
    print_omitted(items.size() - head_count - tail_count);
    for (std::size_t index = items.size() - tail_count; index < items.size();
         ++index) {
        print_item(items[index]);
    }
}

void render_pending_status(std::size_t count) {
    print_status_line(style::yellow,
                      i18n::Key::LabelWarning,
                      i18n::tr(i18n::Key::SyncPartialHeader));
    i18n::println(count == 1 ? i18n::Key::SyncPendingSingular
                             : i18n::Key::SyncPendingPlural,
                  count);
}

void render_pending_paths(const std::vector<std::filesystem::path>& paths,
                          bool full) {
    if (paths.empty()) {
        return;
    }
    render_pending_status(paths.size());
    std::println("{}", i18n::tr(i18n::Key::SyncPendingLabel));

    auto ordered = paths;
    std::ranges::sort(ordered);
    const auto print_path = [](const auto& path) {
        std::println("  {}", platform::path::to_utf8(path));
    };
    const auto print_omitted = [](std::size_t omitted) {
        i18n::println(omitted == 1 ? i18n::Key::SyncPendingOmittedSingular
                                   : i18n::Key::SyncPendingOmittedPlural,
                      omitted);
    };
    render_bounded(ordered, full, print_path, print_omitted);
}

void render_plan_report(const application::PlanReport& report,
                        bool full = false) {
    if (report.has_conflicts) {
        std::println("{}", i18n::tr(i18n::Key::SyncConflictsWarning));
        std::println("{}", i18n::tr(i18n::Key::SyncConflictsStatusHint));
    }

    if (report.items.empty() && report.pending_paths.empty()) {
        std::println("{}", i18n::tr(i18n::Key::SyncNothingToDo));
        return;
    }

    if (report.items.empty()) {
        render_pending_paths(report.pending_paths, full);
        return;
    }

    i18n::println(i18n::Key::SyncPlanHeader, report.items.size());

    constexpr const char* ACTION_NAMES[] = {"RenameLocal",
                                            "Upload",
                                            "CreateLocalDirectory",
                                            "CreateRemoteDirectory",
                                            "MoveLocal",
                                            "Download",
                                            "DeleteLocal",
                                            "DeleteLocalDirectory",
                                            "DeleteRemote",
                                            "DeleteRemoteDirectory",
                                            "CopyLocal",
                                            "DeleteIgnoredLocalFile"};

    auto print_item = [&](const application::PlanItem& item) {
        auto idx = static_cast<std::size_t>(item.action);
        if (idx < std::size(ACTION_NAMES)) {
            std::print("  - [{}] {}",
                       ACTION_NAMES[idx],
                       platform::path::to_utf8(item.path));
            if (item.action == application::PlanAction::RenameLocal ||
                item.action == application::PlanAction::MoveLocal ||
                item.action == application::PlanAction::CopyLocal) {
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

    const auto print_omitted = [](std::size_t omitted) {
        const auto omitted_key = (omitted == 1)
                                     ? i18n::Key::SyncPlanOmittedSingular
                                     : i18n::Key::SyncPlanOmittedPlural;
        std::println("  ... ({}) ...", i18n::format(omitted_key, omitted));
    };
    render_bounded(report.items, full, print_item, print_omitted);

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
    render_pending_paths(report.pending_paths, full);
}

std::string_view entry_name(std::string_view path) {
    const auto separator = path.rfind('/');
    return separator == std::string_view::npos ? path
                                               : path.substr(separator + 1);
}

std::size_t entry_depth(std::string_view path) {
    return 1 + static_cast<std::size_t>(std::ranges::count(path, '/'));
}

template <typename Range, typename Fn>
void render_indexed(const Range& items,
                    Fn&& render,
                    std::string_view prefix = "\n") {
    for (std::size_t index = 0; index < items.size(); ++index) {
        std::println("{}[{}]", prefix, index + 1);
        render(items[index]);
    }
}

int present_remote_heads(const application::RemoteHeadsReport& report) {
    if (report.heads.empty()) {
        std::println("{}", i18n::tr(i18n::Key::RemoteHeadsNone));
        return 0;
    }

    i18n::println(i18n::Key::RemoteHeadsHeader, report.heads.size());
    render_indexed(report.heads, [](const auto& head) {
        i18n::println(i18n::Key::FieldCommit, head.commit_id);
        i18n::println(i18n::Key::FieldHeight, head.height);
        i18n::println(i18n::Key::FieldCreatedAt, head.created_at);
        i18n::println(i18n::Key::FieldParents, head.parent_ids.size());
        i18n::println(i18n::Key::FieldFiles, head.file_count);
        i18n::println(i18n::Key::FieldDirectories, head.directory_count);
        i18n::println(i18n::Key::FieldSize, format_size(head.total_bytes));
        i18n::println(i18n::Key::FieldRoot, head.root_hash);
    });
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
    using S = application::RemoteCommitVariantState;
    static constexpr std::array<std::pair<S, i18n::Key>, 3> kTable{{
        {S::Valid, i18n::Key::VariantValid},
        {S::InvalidCiphertext, i18n::Key::VariantInvalidCiphertext},
        {S::InvalidCommit, i18n::Key::VariantInvalidCommit},
    }};
    return enum_tr(state, kTable, i18n::Key::VariantInvalid);
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
    render_indexed(
        report.variants,
        [](const auto& variant) {
            i18n::println(i18n::Key::FieldCiphertext, variant.ciphertext_id);
            i18n::println(i18n::Key::FieldObject, variant.object_identifier);
            i18n::println(i18n::Key::FieldState, variant_state(variant.state));
        },
        "\n  ");
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
    render_indexed(report.epochs, present_epoch_info);
    return 0;
}

int present_remote_epoch(const application::RemoteEpochReport& report) {
    std::println("{}", i18n::tr(i18n::Key::RemoteEpochDetailHeader));
    present_epoch_info(report.epoch);
    return 0;
}

std::string_view content_state(application::RemoteContentState state) {
    using S = application::RemoteContentState;
    static constexpr std::array<std::pair<S, i18n::Key>, 5> kTable{{
        {S::Present, i18n::Key::ContentStatePresent},
        {S::Missing, i18n::Key::ContentStateMissing},
        {S::Orphan, i18n::Key::ContentStateOrphan},
        {S::Valid, i18n::Key::ContentStateValid},
        {S::Invalid, i18n::Key::ContentStateInvalid},
    }};
    return enum_tr(state, kTable, i18n::Key::ContentStateUnknown);
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
    render_indexed(report.contents, present_content_info);
    return 0;
}

int present_remote_content(const application::RemoteContentReport& report) {
    std::println("{}", i18n::tr(i18n::Key::RemoteContentHeader));
    present_content_info(report.content);
    return 0;
}

std::string_view marker_state(application::RemoteMarkerState state) {
    using S = application::RemoteMarkerState;
    static constexpr std::array<std::pair<S, i18n::Key>, 8> kTable{{
        {S::LogicalHead, i18n::Key::MarkerStateLogicalHead},
        {S::Ancestral, i18n::Key::MarkerStateAncestral},
        {S::InvalidPath, i18n::Key::MarkerStateInvalidPath},
        {S::Missing, i18n::Key::MarkerStateMissing},
        {S::InvalidMarker, i18n::Key::MarkerStateInvalidMarker},
        {S::MissingCommit, i18n::Key::MarkerStateMissingCommit},
        {S::InvalidCiphertext, i18n::Key::MarkerStateInvalidCiphertext},
        {S::InvalidCommit, i18n::Key::MarkerStateInvalidCommit},
    }};
    return enum_tr(state, kTable, i18n::Key::MarkerStateInvalid);
}

int present_remote_markers(const application::RemoteMarkersReport& report) {
    i18n::println(i18n::Key::RemoteMarkersHeader, report.markers.size());
    i18n::println(i18n::Key::FieldLogicalHeads, report.logical_count);
    i18n::println(i18n::Key::FieldAncestralsCount, report.ancestral_count);
    i18n::println(i18n::Key::FieldInvalidCount, report.invalid_count);
    render_indexed(report.markers, [](const auto& marker) {
        i18n::println(i18n::Key::FieldObject, marker.object_identifier);
        i18n::println(i18n::Key::FieldCommit,
                      marker.commit_id.empty() ? "-" : marker.commit_id);
        i18n::println(i18n::Key::FieldCiphertext,
                      marker.ciphertext_id.empty() ? "-"
                                                   : marker.ciphertext_id);
        i18n::println(i18n::Key::FieldState, marker_state(marker.state));
    });
    return 0;
}

std::string_view object_category(application::RemoteObjectCategory category) {
    using C = application::RemoteObjectCategory;
    static constexpr std::array<std::pair<C, i18n::Key>, 7> kTable{{
        {C::Content, i18n::Key::ObjectCategoryContent},
        {C::CommitVariant, i18n::Key::ObjectCategoryCommitVariant},
        {C::HeadMarker, i18n::Key::ObjectCategoryHeadMarker},
        {C::Epoch, i18n::Key::ObjectCategoryEpoch},
        {C::Writer, i18n::Key::ObjectCategoryWriter},
        {C::Barrier, i18n::Key::ObjectCategoryBarrier},
        {C::Protocol, i18n::Key::ObjectCategoryProtocol},
    }};
    return enum_tr(category, kTable, i18n::Key::ObjectCategoryUnknown);
}

int present_remote_objects(const application::RemoteObjectsReport& report) {
    i18n::println(i18n::Key::RemoteObjectsHeader, report.objects.size());
    i18n::println(i18n::Key::FieldUnknownOrInvalid, report.unknown_count);
    render_indexed(report.objects, [](const auto& object) {
        i18n::println(i18n::Key::FieldIdentifier, object.identifier);
        i18n::println(i18n::Key::FieldCategory,
                      object_category(object.category));
        i18n::println(i18n::Key::FieldStructure,
                      object.structurally_valid
                          ? i18n::tr(i18n::Key::FieldStructureValid)
                          : i18n::tr(i18n::Key::FieldStructureInvalid));
        i18n::println(i18n::Key::FieldRelation, object.relation);
    });
    return 0;
}

std::string_view orphan_kind(application::RemoteOrphanKind kind) {
    using K = application::RemoteOrphanKind;
    static constexpr std::array<std::pair<K, i18n::Key>, 6> kTable{{
        {K::Commit, i18n::Key::OrphanKindCommit},
        {K::CommitVariant, i18n::Key::OrphanKindCommitVariant},
        {K::RedundantVariant, i18n::Key::OrphanKindRedundantVariant},
        {K::InvalidVariant, i18n::Key::OrphanKindInvalidVariant},
        {K::Content, i18n::Key::OrphanKindContent},
        {K::ProtectedEpoch, i18n::Key::OrphanKindProtectedEpoch},
    }};
    return enum_tr(kind, kTable, i18n::Key::OrphanKindUnknown);
}

int present_remote_orphans(const application::RemoteOrphansReport& report) {
    i18n::println(i18n::Key::RemoteOrphansHeader, report.objects.size());
    std::println("{}", i18n::tr(i18n::Key::RemoteOrphansReadOnlyHint));
    render_indexed(report.objects, [](const auto& object) {
        i18n::println(i18n::Key::FieldIdentifier, object.identifier);
        i18n::println(i18n::Key::FieldClassification, orphan_kind(object.kind));
        i18n::println(i18n::Key::FieldStructuralCandidate,
                      yes_no(object.removal_candidate));
    });
    return 0;
}

int present_remote_writers(const application::RemoteWritersReport& report) {
    i18n::println(i18n::Key::RemoteWritersHeader, report.writers.size());
    i18n::println(i18n::Key::FieldBarrier,
                  report.barrier_present ? i18n::tr(i18n::Key::FieldPresent)
                                         : i18n::tr(i18n::Key::FieldAbsent));
    if (report.barrier_identifier.has_value()) {
        i18n::println(i18n::Key::FieldIdentifier, *report.barrier_identifier);
    }
    i18n::println(i18n::Key::FieldMaintenanceBlocked,
                  yes_no(report.maintenance_blocked));
    i18n::println(i18n::Key::FieldProtocolConsistent,
                  yes_no(report.protocol_consistent));
    render_indexed(report.writers, [](const auto& writer) {
        i18n::println(i18n::Key::FieldIdentifier, writer.identifier);
        i18n::println(i18n::Key::FieldState,
                      writer.state == application::RemoteWriterState::Invalid
                          ? i18n::tr(i18n::Key::WriterStateInvalid)
                          : i18n::tr(i18n::Key::WriterStateIndeterminate));
    });
    return 0;
}

std::string_view health_state(application::RemoteHealthState state) {
    using S = application::RemoteHealthState;
    static constexpr std::array<std::pair<S, i18n::Key>, 2> kTable{{
        {S::Healthy, i18n::Key::HealthStateHealthy},
        {S::Degraded, i18n::Key::HealthStateDegraded},
    }};
    return enum_tr(state, kTable, i18n::Key::HealthStateCritical);
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
    i18n::println(i18n::Key::FieldUnknownObjects, report.unknown_object_count);
    i18n::println(i18n::Key::FieldReasons, report.reasons.size());
    for (const auto& reason : report.reasons) {
        std::println("    {}", reason);
    }
    return 0;
}

void render_sync_summary(const application::SyncCompleted& summary) {
    if (summary.total == 0) {
        if (summary.partial) {
            render_pending_status(summary.pending);
        } else {
            std::println("      {}", i18n::tr(i18n::Key::SyncEverythingInSync));
        }
        std::println();
        return;
    }

    std::vector<std::string> parts{
        i18n::format(summary.total == 1 ? i18n::Key::SyncChangesSingular
                                        : i18n::Key::SyncChangesPlural,
                     summary.total)};
    const auto push_transfer = [&](std::size_t count,
                                   std::uint64_t bytes,
                                   const char* symbol) {
        if (count > 0) {
            parts.push_back(
                bytes > 0 ? std::format(
                                "{} {} ({})", symbol, count, format_size(bytes))
                          : std::format("{} {}", symbol, count));
        }
    };
    const auto push_count = [&](std::size_t count,
                                i18n::Key single,
                                i18n::Key plural) {
        if (count > 0) {
            parts.push_back(i18n::format(count == 1 ? single : plural, count));
        }
    };
    push_transfer(summary.uploaded, summary.upload_bytes, "↑");
    push_transfer(summary.downloaded, summary.download_bytes, "↓");
    if (summary.removed > 0) {
        parts.push_back(std::format("- {}", summary.removed));
    }
    if (summary.renamed > 0) {
        parts.push_back(std::format("→ {}", summary.renamed));
    }
    push_count(summary.created_dirs,
               i18n::Key::SyncCreatedDirSingular,
               i18n::Key::SyncCreatedDirPlural);
    push_count(summary.removed_dirs,
               i18n::Key::SyncRemovedDirSingular,
               i18n::Key::SyncRemovedDirPlural);
    if (summary.partial) {
        push_count(summary.pending,
                   i18n::Key::SyncPendingSingular,
                   i18n::Key::SyncPendingPlural);
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

int render_inventory_audit(const application::InventoryAuditReport& report) {
    std::println("{}", i18n::tr(i18n::Key::SyncInventoryAuditHeader));
    std::println("{}",
                 i18n::format(i18n::Key::SyncInventoryAuditSummary,
                              report.referenced_content,
                              report.present_content,
                              report.missing_content,
                              report.orphan_content,
                              report.unknown_objects));
    return report.missing_content == 0 && report.orphan_content == 0 &&
                   report.unknown_objects == 0
               ? 0
               : 2;
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

void present(const application::GarbageCollectProgress& progress,
             GarbageCollectProgressDisplayState& state) {
    if (state.last_stage != progress.stage) {
        using S = application::GarbageCollectStage;
        static constexpr std::array<std::pair<S, i18n::Key>, 4> kStages{{
            {S::Preparing, i18n::Key::GcStagePreparing},
            {S::Analyzing, i18n::Key::GcStageAnalyzing},
            {S::Applying, i18n::Key::GcStageApplying},
            {S::Finalizing, i18n::Key::GcStageFinalizing},
        }};
        std::println(
            "{}",
            enum_tr(progress.stage, kStages, i18n::Key::GcStageFinalizing));
        if (progress.stage == S::Finalizing) {
            std::println();
        }
        state.last_stage = progress.stage;
    }

    if (progress.stage == application::GarbageCollectStage::Analyzing &&
        progress.candidate_count.has_value() &&
        state.last_candidate_count != progress.candidate_count) {
        if (*progress.candidate_count == 0) {
            std::println("{}", i18n::tr(i18n::Key::GcCandidatesNone));
        } else {
            std::println("{}",
                         format_plural(*progress.candidate_count,
                                       i18n::Key::GcCandidatesSingular,
                                       i18n::Key::GcCandidatesPlural));
        }
        state.last_candidate_count = progress.candidate_count;
    }
}

void present(const application::FsckProgress& progress,
             FsckProgressDisplayState& state) {
    if (state.last_stage != progress.stage) {
        using S = application::FsckStage;
        static constexpr std::array<std::pair<S, i18n::Key>, 5> kStages{{
            {S::Preparing, i18n::Key::FsckStagePreparing},
            {S::Observing, i18n::Key::FsckStageObserving},
            {S::Analyzing, i18n::Key::FsckStageAnalyzing},
            {S::AuditingContent, i18n::Key::FsckStageAuditingContent},
            {S::Finalizing, i18n::Key::FsckStageFinalizing},
        }};
        std::println(
            "{}",
            enum_tr(progress.stage, kStages, i18n::Key::FsckStageFinalizing));
        state.last_stage = progress.stage;
    }

    if (progress.stage != application::FsckStage::AuditingContent) {
        return;
    }
    if (!progress.total_objects.has_value()) {
        return;
    }
    if (*progress.total_objects == 0) {
        if (!state.empty_inventory_reported) {
            std::println("{}", i18n::tr(i18n::Key::FsckNoContent));
            state.empty_inventory_reported = true;
        }
        return;
    }

    const auto calc_percent = [](std::uint64_t done, std::uint64_t total) {
        return done == total ? 100u
                             : static_cast<unsigned>(
                                   static_cast<long double>(done) * 100.0L /
                                   static_cast<long double>(total));
    };
    const auto completed =
        std::min(progress.completed_objects, *progress.total_objects);
    const auto percent = calc_percent(completed, *progress.total_objects);
    if (state.last_object_percent == percent) {
        return;
    }
    state.last_object_percent = percent;

    std::string line = i18n::format(*progress.total_objects == 1
                                        ? i18n::Key::FsckProgressObject
                                        : i18n::Key::FsckProgressObjects,
                                    completed,
                                    *progress.total_objects,
                                    percent);
    if (progress.completed_plaintext_bytes.has_value() &&
        progress.total_plaintext_bytes.has_value()) {
        const auto completed_bytes =
            std::min(*progress.completed_plaintext_bytes,
                     *progress.total_plaintext_bytes);
        const auto completed_size = format_size(completed_bytes);
        const auto total_size = format_size(*progress.total_plaintext_bytes);
        if (*progress.total_plaintext_bytes == 0) {
            line += i18n::format(
                i18n::Key::FsckProgressBytes, completed_size, total_size);
        } else {
            line += i18n::format(
                i18n::Key::FsckProgressBytesPercent,
                completed_size,
                total_size,
                calc_percent(completed_bytes, *progress.total_plaintext_bytes));
        }
    }
    std::println("{}.", line);
}

int present(const application::Response& response, bool full) {
    if (const auto* sync =
            std::get_if<application::SyncCompleted>(&response.data);
        sync && response.operation == application::Operation::Sync) {
        int exit_code = 0;
        if (sync->partial) {
            render_pending_paths(sync->pending_paths, full);
            exit_code = 2;
        } else {
            print_ok_line(i18n::tr(i18n::Key::SyncCompleted));
        }
        if (sync->trusted_content_reused > 0) {
            std::println("{}",
                         i18n::format(i18n::Key::SyncTrustedContentWarning,
                                      sync->trusted_content_reused));
        }
        if (response.inventory_audit) {
            exit_code = std::max(
                exit_code, render_inventory_audit(*response.inventory_audit));
        }
        return exit_code;
    }
    if (const auto* ptr = std::get_if<application::PlanReport>(&response.data);
        ptr && (response.operation == application::Operation::Preview ||
                response.operation == application::Operation::Status)) {
        render_plan_report(*ptr, full);
        if (response.operation == application::Operation::Preview) {
            std::println("{}", i18n::tr(i18n::Key::PreviewCompleted));
        }
        return ptr->pending_paths.empty() ? 0 : 2;
    }
    if (const auto* fsck =
            std::get_if<application::FsckCompleted>(&response.data);
        fsck && response.operation == application::Operation::Fsck) {
        print_ok_line(i18n::tr(i18n::Key::ErrorFsckClean));
        std::println("{}",
                     format_plural(fsck->checked_objects,
                                   i18n::Key::FsckSummarySingular,
                                   i18n::Key::FsckSummaryPlural));
        if (fsck->checked_plaintext_bytes.has_value()) {
            std::println(
                "{}",
                i18n::format(i18n::Key::FsckSummaryBytes,
                             format_size(*fsck->checked_plaintext_bytes)));
        }
        return 0;
    }
    if (response.operation == application::Operation::RemoveWriter) {
        if (const auto* ptr =
                std::get_if<application::ManualWriterRemovalCompleted>(
                    &response.data)) {
            print_ok_line(i18n::format(i18n::Key::ManualWriterRemovalCompleted,
                                       ptr->identifier));
            return 0;
        }
    }
    if (response.operation == application::Operation::RemoveBarrier) {
        if (const auto* ptr =
                std::get_if<application::ManualBarrierRemovalCompleted>(
                    &response.data)) {
            print_ok_line(
                ptr->outcome == application::BarrierRemovalOutcome::Removed
                    ? i18n::format(i18n::Key::ManualBarrierRemovalCompleted,
                                   ptr->identifier)
                    : std::string{
                          i18n::tr(i18n::Key::ManualBarrierRemovalAbsent)});
            if (ptr->active_writers_count > 0) {
                std::println(
                    "{} {}",
                    i18n::tr(i18n::Key::LabelWarning),
                    i18n::format(i18n::Key::ManualBarrierRemovalWritersRemain,
                                 ptr->active_writers_count));
            }
            return 0;
        }
    }
    if (const auto* ptr =
            std::get_if<application::GarbageCollectCompleted>(&response.data);
        ptr && response.operation == application::Operation::GarbageCollect) {
        if (ptr->analysis_only) {
            const auto header =
                format_plural(ptr->candidate_objects,
                              i18n::Key::GcWarningHeaderSingular,
                              i18n::Key::GcWarningHeaderPlural);
            const auto label = i18n::tr(i18n::Key::LabelWarning);
            const std::string indent(label.size() + 1, ' ');
            print_status_line(style::yellow, i18n::Key::LabelWarning, header);
            std::println("{}{}", indent, i18n::tr(i18n::Key::GcWarningDetail1));
            std::println("{}{}", indent, i18n::tr(i18n::Key::GcWarningDetail2));
            return 0;
        }
        print_ok_line(i18n::tr(i18n::Key::GcCompleted));
        std::println(
            "     {}",
            i18n::format(i18n::Key::GcSummary, ptr->candidate_objects));
        return 0;
    }
    if (const auto* ptr =
            std::get_if<application::ResolveMissingCompleted>(&response.data);
        ptr && response.operation == application::Operation::ResolveMissing) {
        if (ptr->resolved_count > 0) {
            print_ok_line(format_plural(ptr->resolved_count,
                                        i18n::Key::ResolveMissingSingular,
                                        i18n::Key::ResolveMissingPlural));
        } else {
            std::println("{}", i18n::tr(i18n::Key::ResolveMissingNone));
        }
        return 0;
    }
    return 1;
}

int present(const application::InspectionResponse& response) {
    const auto match = [&]<typename Report>(
                           application::InspectionOperation expected,
                           int (*render)(const Report&)) -> std::optional<int> {
        if (response.operation != expected) {
            return std::nullopt;
        }
        if (const auto* report = std::get_if<Report>(&response.payload)) {
            return render(*report);
        }
        return std::nullopt;
    };
    const std::optional<int> rendered[] = {
        match(application::InspectionOperation::RemoteHeads,
              present_remote_heads),
        match(application::InspectionOperation::RemoteTree,
              present_remote_tree),
        match(application::InspectionOperation::RemoteCommits,
              present_remote_commits),
        match(application::InspectionOperation::RemoteSummary,
              present_remote_summary),
        match(application::InspectionOperation::RemoteStat,
              present_remote_stat),
        match(application::InspectionOperation::RemoteCommit,
              present_remote_commit),
        match(application::InspectionOperation::RemoteGet, present_remote_file),
        match(application::InspectionOperation::RemoteEpochs,
              present_remote_epochs),
        match(application::InspectionOperation::RemoteEpoch,
              present_remote_epoch),
        match(application::InspectionOperation::RemoteContents,
              present_remote_contents),
        match(application::InspectionOperation::RemoteContentsAudit,
              present_remote_contents),
        match(application::InspectionOperation::RemoteContent,
              present_remote_content),
        match(application::InspectionOperation::RemoteMarkers,
              present_remote_markers),
        match(application::InspectionOperation::RemoteObjects,
              present_remote_objects),
        match(application::InspectionOperation::RemoteOrphans,
              present_remote_orphans),
        match(application::InspectionOperation::RemoteWriters,
              present_remote_writers),
        match(application::InspectionOperation::RemoteHealth,
              present_remote_health),
    };
    for (const auto& code : rendered) {
        if (code.has_value()) {
            return *code;
        }
    }

    print_status_line(style::red,
                      i18n::Key::LabelError,
                      i18n::tr(i18n::Key::ErrorInconsistentInspection));
    return 1;
}

namespace {

std::string sanitize_error_detail(std::string_view detail) {
    std::string result{detail};
    struct TokenReplacement {
        std::string_view token;
        std::string_view pt;
        std::string_view en;
    };
    constexpr std::array<TokenReplacement, 4> tokens = {{
        {"CommitUploaded", "commit publicado", "published commit"},
        {"HeadVerified", "head verificada", "verified head"},
        {"EpochPrepared", "epoch preparado", "prepared epoch"},
        {"DatabaseCommitted", "estado persistido", "persisted state"},
    }};
    const bool is_pt = i18n::current_language() == i18n::Language::Portuguese;
    for (const auto& entry : tokens) {
        const auto replacement = is_pt ? entry.pt : entry.en;
        std::size_t pos = 0;
        while ((pos = result.find(entry.token, pos)) != std::string::npos) {
            result.replace(pos, entry.token.length(), replacement);
            pos += replacement.length();
        }
    }
    return result;
}

} // namespace

int present(const application::Error& error) {
    if (platform::cancellation::requested() ||
        error.detail.find("cancelled by user") != std::string::npos) {
        return present_cancellation(error.operation);
    }

    if ((error.operation == application::Operation::Sync ||
         error.operation == application::Operation::Preview ||
         error.operation == application::Operation::Status) &&
        error.stage.has_value()) {
        using S = application::SyncStage;
        static constexpr std::array<std::pair<S, i18n::Key>, 5> kStages{{
            {S::Observing, i18n::Key::SyncErrorObserving},
            {S::Calculating, i18n::Key::SyncErrorCalculating},
            {S::Applying, i18n::Key::SyncErrorApplying},
            {S::Publishing, i18n::Key::SyncErrorPublishing},
            {S::Finalizing, i18n::Key::SyncErrorFinalizing},
        }};
        print_error_line(
            enum_tr(*error.stage, kStages, i18n::Key::SyncErrorObserving));
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
            print_error_line(error.detail);
            break;
        case application::ErrorCode::PlanFailure:
            print_error_line(
                i18n::format(i18n::Key::ErrorPlanCalculation, error.detail));
            break;
        case application::ErrorCode::FsckFailure:
            std::println("{}", i18n::tr(i18n::Key::ErrorFsckAuditing));
            print_error_line(
                i18n::format(i18n::Key::ErrorFsckFailed, error.detail));
            break;
        case application::ErrorCode::GarbageCollectionFailure:
            print_error_line(
                i18n::format(i18n::Key::ErrorGcCancelled, error.detail));
            break;
        case application::ErrorCode::WriterRemovalFailure:
            print_error_line(i18n::format(i18n::Key::ErrorWriterRemovalFailed,
                                          error.detail));
            break;
        case application::ErrorCode::BarrierRemovalFailure:
            print_error_line(i18n::format(i18n::Key::ErrorBarrierRemovalFailed,
                                          error.detail));
            if (error.barrier_removal) {
                const auto& br = *error.barrier_removal;
                using Stg = application::BarrierRemovalStage;
                using Mst = application::BarrierRemovalMutationState;
                static constexpr std::array<std::pair<Stg, i18n::Key>, 7>
                    kBarrierStages{{
                        {Stg::CheckingPresence,
                         i18n::Key::BarrierRemovalStageCheckingPresence},
                        {Stg::DownloadingPayload,
                         i18n::Key::BarrierRemovalStageDownloadingPayload},
                        {Stg::ValidatingPayload,
                         i18n::Key::BarrierRemovalStageValidatingPayload},
                        {Stg::CheckingWriters,
                         i18n::Key::BarrierRemovalStageCheckingWriters},
                        {Stg::VerifyingPhysicalIdentity,
                         i18n::Key::
                             BarrierRemovalStageVerifyingPhysicalIdentity},
                        {Stg::Removing, i18n::Key::BarrierRemovalStageRemoving},
                        {Stg::ConfirmingAbsence,
                         i18n::Key::BarrierRemovalStageConfirmingAbsence},
                    }};
                static constexpr std::array<std::pair<Mst, i18n::Key>, 3>
                    kMutationStates{{
                        {Mst::NotAttempted,
                         i18n::Key::BarrierRemovalMutationNotAttempted},
                        {Mst::Confirmed,
                         i18n::Key::BarrierRemovalMutationConfirmed},
                        {Mst::Uncertain,
                         i18n::Key::BarrierRemovalMutationUncertain},
                    }};
                std::println(
                    "  {}: {}",
                    i18n::tr(i18n::Key::LabelStage),
                    enum_tr(br.stage,
                            kBarrierStages,
                            i18n::Key::BarrierRemovalStageCheckingPresence));
                std::println(
                    "  {}: {}",
                    i18n::tr(i18n::Key::LabelMutationState),
                    enum_tr(br.mutation_state,
                            kMutationStates,
                            i18n::Key::BarrierRemovalMutationNotAttempted));
                if (br.transport_error) {
                    std::println("  {}: {}",
                                 i18n::tr(i18n::Key::LabelTransportError),
                                 transport::describe(*br.transport_error));
                }
            }
            break;
        case application::ErrorCode::InventoryAuditFailure:
            print_error_line(i18n::format(i18n::Key::ErrorInventoryAuditFailed,
                                          error.detail));
            if (error.sync_completed) {
                std::println(
                    "{}",
                    i18n::tr(i18n::Key::ErrorInventoryAuditSyncCompleted));
                if (error.sync_completed->partial) {
                    render_pending_status(error.sync_completed->pending);
                }
                if (error.sync_completed->published) {
                    std::println(
                        "{}",
                        i18n::tr(i18n::Key::ErrorInventoryAuditPublished));
                }
            }
            break;
        case application::ErrorCode::SynchronizationFailure:
        case application::ErrorCode::RecoveryFailure:
            print_error_line(
                i18n::format(i18n::Key::ErrorSyncFailed, error.detail));
            break;
    }
    return 1;
}

int present(const application::InspectionError& error) {
    print_error_line(error.detail);
    if (error.code == application::InspectionErrorCode::HeadSelectionRequired ||
        (error.code == application::InspectionErrorCode::RemoteHeadNotFound &&
         !error.candidate_ids.empty())) {
        std::println("{}", i18n::tr(i18n::Key::ErrorAvailableHeads));
        for (const auto& id : error.candidate_ids) {
            std::println("  {}", id);
        }
        if (error.code ==
            application::InspectionErrorCode::HeadSelectionRequired) {
            std::println("{}", i18n::tr(i18n::Key::ErrorUseRemoteTreeHead));
        }
    }
    return 1;
}

} // namespace kasumi::cli
