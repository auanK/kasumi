#include "cli/presenter.hpp"

#include "cli/help_topics.hpp"
#include "cli/i18n.hpp"
#include "cli/style.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <format>
#include <print>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
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

std::string sanitize_terminal_text(std::string_view text) {
    std::string cleaned;
    cleaned.reserve(text.size());
    for (std::size_t index = 0; index < text.size(); ++index) {
        const auto byte = static_cast<unsigned char>(text[index]);
        if (byte == 0xC2U && index + 1 < text.size()) {
            const auto next = static_cast<unsigned char>(text[index + 1]);
            if (next >= 0x80U && next <= 0x9FU) {
                cleaned.push_back('?');
                ++index;
                continue;
            }
        }
        if (byte >= 0xC2U && byte <= 0xF4U) {
            const std::size_t width = byte < 0xE0U ? 2 : byte < 0xF0U ? 3 : 4;
            if (width <= text.size() - index &&
                std::ranges::all_of(text.substr(index + 1, width - 1),
                                    [](unsigned char next) {
                                        return next >= 0x80U && next <= 0xBFU;
                                    })) {
                cleaned.append(text.substr(index, width));
                index += width - 1;
                continue;
            }
        }
        if ((byte < 0x20U && byte != '\n' && byte != '\t') ||
            (byte >= 0x7FU && byte <= 0x9FU)) {
            cleaned.push_back('?');
            continue;
        }
        cleaned.push_back(text[index]);
    }
    return cleaned;
}

void print_status_line(std::string_view color,
                       i18n::Key label,
                       std::string_view message) {
    const bool use_color = platform::stdout_terminal().ansi;
    std::println("{}{}{} {}",
                 use_color ? color : std::string_view{},
                 i18n::tr(label),
                 use_color ? std::string_view{style::reset}
                           : std::string_view{},
                 sanitize_terminal_text(message));
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
    for (const auto& [name, key] : help_topics) {
        if (name == topic) {
            std::print("{}{}", i18n::tr(key), i18n::tr(i18n::Key::HelpOptions));
            return 0;
        }
    }
    std::print("{}", i18n::tr(i18n::Key::HelpText));
    return 0;
}

int present_parse_error(std::string_view topic) {
    const std::string sanitized_topic = sanitize_terminal_text(topic);
    const std::string suffix =
        sanitized_topic.empty() ? "" : " " + sanitized_topic;
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
    i18n::println(i18n::Key::SyncPendingLabel);

    auto ordered = paths;
    std::ranges::sort(ordered);
    const auto print_path = [](const auto& path) {
        std::println("  {}",
                     sanitize_terminal_text(platform::path::to_utf8(path)));
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
        i18n::println(i18n::Key::SyncConflictsWarning);
        i18n::println(i18n::Key::SyncConflictsStatusHint);
    }

    if (report.items.empty() && report.pending_paths.empty()) {
        i18n::println(i18n::Key::SyncNothingToDo);
        return;
    }

    if (report.items.empty()) {
        render_pending_paths(report.pending_paths, full);
        return;
    }

    i18n::println(i18n::Key::SyncPlanHeader, report.items.size());

    static constexpr auto action_keys = std::to_array<i18n::Key>({
        i18n::Key::SyncActionRenameLocal,
        i18n::Key::SyncActionUpload,
        i18n::Key::SyncActionCreateLocalDirectory,
        i18n::Key::SyncActionCreateRemoteDirectory,
        i18n::Key::SyncActionMoveLocal,
        i18n::Key::SyncActionDownload,
        i18n::Key::SyncActionDeleteLocal,
        i18n::Key::SyncActionDeleteLocalDirectory,
        i18n::Key::SyncActionDeleteRemote,
        i18n::Key::SyncActionDeleteRemoteDirectory,
        i18n::Key::SyncActionCopyLocal,
        i18n::Key::SyncActionDeleteIgnoredLocalFile,
    });
    static_assert(action_keys.size() == application::PLAN_ACTION_COUNT);

    auto print_item = [&](const application::PlanItem& item) {
        auto idx = static_cast<std::size_t>(item.action);
        if (idx < action_keys.size()) {
            std::print(
                "  - [{}] {}",
                i18n::tr(action_keys[idx]),
                sanitize_terminal_text(platform::path::to_utf8(item.path)));
            if (item.action == application::PlanAction::RenameLocal ||
                item.action == application::PlanAction::MoveLocal ||
                item.action == application::PlanAction::CopyLocal) {
                std::print(" -> {}",
                           sanitize_terminal_text(
                               platform::path::to_utf8(item.alternative_path)));
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

    i18n::println(i18n::Key::SyncSummaryHeader);
    for (std::size_t i = 0; i < report.action_counts.size(); ++i) {
        if (report.action_counts[i] > 0) {
            if (i < action_keys.size()) {
                std::println("  {}: {}",
                             i18n::tr(action_keys[i]),
                             report.action_counts[i]);
            }
        }
    }

    if (report.upload_bytes > 0 || report.download_bytes > 0) {
        i18n::println(i18n::Key::SyncEstimatedTraffic);
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

std::string remote_text(std::string_view text) {
    auto cleaned = sanitize_terminal_text(text);
    std::ranges::replace(cleaned, '\n', '?');
    std::ranges::replace(cleaned, '\t', '?');
    return cleaned;
}

template <typename Report>
int present_remote_report(const Report& report) = delete;

int present_remote_report(const application::RemoteHeadsReport& report) {
    if (report.heads.empty()) {
        i18n::println(i18n::Key::RemoteHeadsNone);
        return 0;
    }

    i18n::println(i18n::Key::RemoteHeadsHeader, report.heads.size());
    render_indexed(report.heads, [](const auto& head) {
        i18n::println(i18n::Key::FieldCommit, remote_text(head.commit_id));
        i18n::println(i18n::Key::FieldHeight, head.height);
        i18n::println(i18n::Key::FieldCreatedAt, head.created_at);
        i18n::println(i18n::Key::FieldParents, head.parent_ids.size());
        i18n::println(i18n::Key::FieldFiles, head.file_count);
        i18n::println(i18n::Key::FieldDirectories, head.directory_count);
        i18n::println(i18n::Key::FieldSize, format_size(head.total_bytes));
        i18n::println(i18n::Key::FieldRoot, remote_text(head.root_hash));
    });
    return 0;
}

int present_remote_report(const application::RemoteTreeReport& report) {
    if (!report.history_present) {
        i18n::println(i18n::Key::RemoteTreeNone);
        return 0;
    }

    i18n::println(i18n::Key::RemoteTreeHead, remote_text(report.commit_id));
    i18n::println(i18n::Key::RemoteTreeHeight, report.height);
    i18n::println(i18n::Key::RemoteTreeFiles, report.file_count);
    i18n::println(i18n::Key::RemoteTreeDirectories, report.directory_count);
    i18n::println(i18n::Key::RemoteTreeSize, format_size(report.total_bytes));
    std::println("\n/");
    for (const auto& entry : report.entries) {
        const auto indent = std::string(entry_depth(entry.path) * 2, ' ');
        const auto name = remote_text(entry_name(entry.path));
        if (entry.type == application::RemoteTreeEntryType::Directory) {
            std::println("{}{}/", indent, name);
        } else {
            std::println("{}{}  {}", indent, name, format_size(entry.size));
        }
    }
    return 0;
}

int present_remote_report(const application::RemoteCommitsReport& report) {
    if (!report.history_present) {
        i18n::println(i18n::Key::RemoteCommitsNone);
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
        i18n::println(i18n::Key::FieldCommit, remote_text(commit.commit_id));
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

std::string_view dash_or(std::string_view value) {
    return value.empty() ? "-" : value;
}

int present_remote_report(const application::RemoteSummaryReport& report) {
    i18n::println(i18n::Key::RemoteSummaryHeader);
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

int present_remote_report(const application::RemoteStatReport& report) {
    i18n::println(i18n::Key::RemoteStatHeader);
    i18n::println(i18n::Key::RemoteStatView);
    i18n::println(i18n::Key::FieldHeight, report.observed_height);
    i18n::println(i18n::Key::FieldConflicts, yes_no(report.has_conflicts));
    i18n::println(i18n::Key::FieldPath, remote_text(report.path));
    i18n::println(i18n::Key::FieldType,
                  report.type == application::RemoteTreeEntryType::Directory
                      ? i18n::tr(i18n::Key::RemoteStatDirectory)
                      : i18n::tr(i18n::Key::RemoteStatFile));
    i18n::println(i18n::Key::FieldLogicalHash,
                  remote_text(report.logical_hash));
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

int present_remote_report(const application::RemoteCommitReport& report) {
    const auto& commit = report.commit;
    i18n::println(i18n::Key::RemoteCommitHeader);
    i18n::println(i18n::Key::FieldCommit, remote_text(commit.commit_id));
    i18n::println(i18n::Key::FieldHeight, commit.height);
    i18n::println(i18n::Key::FieldCreatedAt, commit.created_at);
    i18n::println(i18n::Key::FieldLogicalHead, yes_no(commit.logical_head));
    i18n::println(i18n::Key::FieldPhysicalMarker,
                  yes_no(commit.physically_marked));
    i18n::println(i18n::Key::FieldAncestralMarker,
                  yes_no(commit.ancestral_marked));
    i18n::println(i18n::Key::FieldRoot, remote_text(commit.root_hash));
    i18n::println(i18n::Key::FieldEntries, commit.entry_count);
    i18n::println(i18n::Key::FieldSize, format_size(commit.total_bytes));
    i18n::println(i18n::Key::FieldParentsCount, commit.parent_ids.size());
    for (const auto& parent : commit.parent_ids) {
        std::println("    {}", remote_text(parent));
    }
    i18n::println(i18n::Key::FieldPhysicalVariants, report.variants.size());
    render_indexed(
        report.variants,
        [](const auto& variant) {
            i18n::println(i18n::Key::FieldCiphertext,
                          remote_text(variant.ciphertext_id));
            i18n::println(i18n::Key::FieldObject,
                          remote_text(variant.object_identifier));
            i18n::println(i18n::Key::FieldState, variant_state(variant.state));
        },
        "\n  ");
    return 0;
}

int present_remote_report(const application::RemoteFileReport& report) {
    i18n::println(i18n::Key::RemoteFileSavedHeader);
    i18n::println(i18n::Key::FieldPath, remote_text(report.path));
    i18n::println(i18n::Key::FieldDestination,
                  remote_text(report.destination_path));
    i18n::println(i18n::Key::FieldLogicalHash,
                  remote_text(report.logical_hash));
    i18n::println(i18n::Key::FieldSize, format_size(report.size));
    return 0;
}

void present_epoch_info(const application::RemoteEpochInfo& epoch) {
    i18n::println(i18n::Key::FieldSequence, epoch.sequence);
    i18n::println(i18n::Key::FieldEpochId, remote_text(epoch.epoch_id));
    i18n::println(i18n::Key::FieldVaultId, remote_text(epoch.vault_id));
    i18n::println(i18n::Key::FieldIssuedAt, epoch.issued_at);
    i18n::println(i18n::Key::FieldMinRetention,
                  epoch.min_history_depth,
                  epoch.min_history_age_hours);
    i18n::println(i18n::Key::FieldPreviousEpoch,
                  remote_text(dash_or(epoch.previous_epoch_id)));
    i18n::println(i18n::Key::FieldNextEpoch,
                  remote_text(dash_or(epoch.next_epoch_id)));
    i18n::println(i18n::Key::FieldAnchors, epoch.anchors.size());
    for (const auto& anchor : epoch.anchors) {
        std::println("    {}",
                     i18n::format(i18n::Key::FieldAnchorItem,
                                  remote_text(anchor.commit_id),
                                  anchor.height));
    }
}

int present_remote_report(const application::RemoteEpochsReport& report) {
    i18n::println(i18n::Key::RemoteEpochsHeader, report.epochs.size());
    render_indexed(report.epochs, present_epoch_info);
    return 0;
}

int present_remote_report(const application::RemoteEpochReport& report) {
    i18n::println(i18n::Key::RemoteEpochDetailHeader);
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
    i18n::println(i18n::Key::FieldContentId, remote_text(content.content_id));
    i18n::println(i18n::Key::FieldState, content_state(content.state));
    i18n::println(i18n::Key::FieldReferenced, yes_no(content.referenced));
    i18n::println(i18n::Key::FieldPhysicallyPresent,
                  yes_no(content.physically_present));
    i18n::println(i18n::Key::FieldCurrentTree, yes_no(content.current_tree));
    i18n::println(i18n::Key::FieldLogicalHash,
                  remote_text(dash_or(content.logical_hash)));
    i18n::println(i18n::Key::FieldLogicalSize, content.size);
    i18n::println(i18n::Key::FieldPathsCount, content.paths.size());
    for (const auto& path : content.paths) {
        std::println("    {}", remote_text(path));
    }
}

int present_remote_report(const application::RemoteContentsReport& report) {
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

int present_remote_report(const application::RemoteContentReport& report) {
    i18n::println(i18n::Key::RemoteContentHeader);
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

int present_remote_report(const application::RemoteMarkersReport& report) {
    i18n::println(i18n::Key::RemoteMarkersHeader, report.markers.size());
    i18n::println(i18n::Key::FieldLogicalHeads, report.logical_count);
    i18n::println(i18n::Key::FieldAncestralsCount, report.ancestral_count);
    i18n::println(i18n::Key::FieldInvalidCount, report.invalid_count);
    render_indexed(report.markers, [](const auto& marker) {
        i18n::println(i18n::Key::FieldObject,
                      remote_text(marker.object_identifier));
        i18n::println(i18n::Key::FieldCommit,
                      remote_text(dash_or(marker.commit_id)));
        i18n::println(i18n::Key::FieldCiphertext,
                      remote_text(dash_or(marker.ciphertext_id)));
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

int present_remote_report(const application::RemoteObjectsReport& report) {
    i18n::println(i18n::Key::RemoteObjectsHeader, report.objects.size());
    i18n::println(i18n::Key::FieldUnknownOrInvalid, report.unknown_count);
    render_indexed(report.objects, [](const auto& object) {
        i18n::println(i18n::Key::FieldIdentifier,
                      remote_text(object.identifier));
        i18n::println(i18n::Key::FieldCategory,
                      object_category(object.category));
        i18n::println(i18n::Key::FieldStructure,
                      object.structurally_valid
                          ? i18n::tr(i18n::Key::FieldStructureValid)
                          : i18n::tr(i18n::Key::FieldStructureInvalid));
        i18n::println(i18n::Key::FieldRelation, remote_text(object.relation));
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

int present_remote_report(const application::RemoteOrphansReport& report) {
    i18n::println(i18n::Key::RemoteOrphansHeader, report.objects.size());
    i18n::println(i18n::Key::RemoteOrphansReadOnlyHint);
    render_indexed(report.objects, [](const auto& object) {
        i18n::println(i18n::Key::FieldIdentifier,
                      remote_text(object.identifier));
        i18n::println(i18n::Key::FieldClassification, orphan_kind(object.kind));
        i18n::println(i18n::Key::FieldStructuralCandidate,
                      yes_no(object.removal_candidate));
    });
    return 0;
}

int present_remote_report(const application::RemoteWritersReport& report) {
    i18n::println(i18n::Key::RemoteWritersHeader, report.writers.size());
    i18n::println(i18n::Key::FieldBarrier,
                  report.barrier_present ? i18n::tr(i18n::Key::FieldPresent)
                                         : i18n::tr(i18n::Key::FieldAbsent));
    if (report.barrier_identifier.has_value()) {
        i18n::println(i18n::Key::FieldIdentifier,
                      remote_text(*report.barrier_identifier));
    }
    i18n::println(i18n::Key::FieldMaintenanceBlocked,
                  yes_no(report.maintenance_blocked));
    i18n::println(i18n::Key::FieldProtocolConsistent,
                  yes_no(report.protocol_consistent));
    render_indexed(report.writers, [](const auto& writer) {
        i18n::println(i18n::Key::FieldIdentifier,
                      remote_text(writer.identifier));
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

int present_remote_report(const application::RemoteHealthReport& report) {
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
        std::println("    {}", remote_text(reason));
    }
    return 0;
}

bool inspection_op_matches(
    const application::InspectionResponse& response) noexcept {
    using Op = application::InspectionOperation;
    // Keep this table in InspectionPayload variant order.
    constexpr std::array operations{Op::RemoteHeads,
                                    Op::RemoteTree,
                                    Op::RemoteCommits,
                                    Op::RemoteSummary,
                                    Op::RemoteStat,
                                    Op::RemoteCommit,
                                    Op::RemoteGet,
                                    Op::RemoteEpochs,
                                    Op::RemoteEpoch,
                                    Op::RemoteContents,
                                    Op::RemoteContent,
                                    Op::RemoteMarkers,
                                    Op::RemoteObjects,
                                    Op::RemoteOrphans,
                                    Op::RemoteWriters,
                                    Op::RemoteHealth};
    static_assert(operations.size() ==
                  std::variant_size_v<application::InspectionPayload>);
    return response.operation == operations[response.payload.index()] ||
           (response.operation == Op::RemoteContentsAudit &&
            std::holds_alternative<application::RemoteContentsReport>(
                response.payload));
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

unsigned progress_percent(std::uint64_t done, std::uint64_t total) noexcept {
    if (total == 0) {
        return 0;
    }
    return done >= total
               ? 100u
               : std::min(99u,
                          static_cast<unsigned>(static_cast<long double>(done) *
                                                100.0L / total));
}

int render_inventory_audit(const application::InventoryAuditReport& report) {
    i18n::println(i18n::Key::SyncInventoryAuditHeader);
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
        if (progress.stage == application::SyncStage::Observing) {
            i18n::println(i18n::Key::PlanStageObserving);
        } else if (progress.stage == application::SyncStage::Calculating) {
            std::println("{}\n", i18n::tr(i18n::Key::PlanStageCalculating));
        }
        return;
    }

    if (progress.stage == application::SyncStage::Calculating &&
        progress.summary) {
        render_sync_summary(*progress.summary);
        return;
    }
    using S = application::SyncStage;
    static constexpr std::array<std::pair<S, i18n::Key>, 5> kStages{{
        {S::Observing, i18n::Key::SyncStageObserving},
        {S::Calculating, i18n::Key::SyncStageCalculating},
        {S::Applying, i18n::Key::SyncStageApplying},
        {S::Publishing, i18n::Key::SyncStagePublishing},
        {S::Finalizing, i18n::Key::SyncStageFinalizing},
    }};
    std::println(
        "{}", enum_tr(progress.stage, kStages, i18n::Key::SyncStageFinalizing));
    if (progress.stage == S::Finalizing) {
        std::println();
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
        progress.listed_objects) {
        i18n::println(i18n::Key::GcListedObjects, *progress.listed_objects);
    }

    if (progress.stage == application::GarbageCollectStage::Analyzing &&
        progress.candidate_count.has_value() &&
        state.last_candidate_count != progress.candidate_count) {
        if (*progress.candidate_count == 0) {
            i18n::println(i18n::Key::GcCandidatesNone);
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
            i18n::println(i18n::Key::FsckNoContent);
            state.empty_inventory_reported = true;
        }
        return;
    }

    const auto completed =
        std::min(progress.completed_objects, *progress.total_objects);
    const auto percent = progress_percent(completed, *progress.total_objects);
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
            line +=
                i18n::format(i18n::Key::FsckProgressBytesPercent,
                             completed_size,
                             total_size,
                             progress_percent(completed_bytes,
                                              *progress.total_plaintext_bytes));
        }
    }
    std::println("{}.", line);
}

std::string format_eta(std::uint64_t seconds) {
    using K = i18n::Key;
    if (seconds >= 3600) {
        return i18n::format(
            K::ProgressHours, seconds / 3600, (seconds / 60) % 60);
    }
    if (seconds >= 60) {
        return i18n::format(K::ProgressMinutes, seconds / 60, seconds % 60);
    }
    return i18n::format(K::ProgressSeconds, seconds);
}

namespace {

bool is_byte_transfer(application::Activity activity) noexcept {
    using A = application::Activity;
    return activity == A::Uploading || activity == A::Downloading ||
           activity == A::Auditing;
}

i18n::Key progress_label(const application::ActivityProgress& event,
                         bool show_batch = false) noexcept {
    using A = application::Activity;
    using K = i18n::Key;
    static constexpr std::array labels{
        K::ProgressScanning,
        K::ProgressStaging,
        K::ProgressUploading,
        K::ProgressDownloading,
        K::ProgressVerifying,
        K::ProgressInstalling,
        K::ProgressReobserving,
        K::ProgressListing,
        K::ProgressAuthenticating,
        K::ProgressAuditing,
        K::ProgressRemoving,
        K::ProgressComparingSnapshots,
        K::ProgressCheckingRemoteContent,
        K::ProgressPreparingPlan,
        K::ProgressPreparingRemote,
    };
    if (show_batch && event.total_objects && event.item_path.empty()) {
        switch (event.activity) {
            case A::Uploading:
                return K::ProgressUploadingBatch;
            case A::Downloading:
                return K::ProgressDownloadingBatch;
            case A::Verifying:
                return K::ProgressVerifyingBatch;
            default:
                break;
        }
    }
    return labels[static_cast<std::size_t>(event.activity)];
}

std::string progress_count(application::Activity activity,
                           std::uint64_t done,
                           std::uint64_t total) {
    using K = i18n::Key;
    const auto key = activity == application::Activity::PreparingPlan
                         ? K::ProgressFractionChanges
                         : (total == 1 ? K::ProgressFractionObject
                                       : K::ProgressFractionObjects);
    return i18n::format(key, done, total);
}

std::string format_bytes_rate(double bytes_per_second) {
    return i18n::format(i18n::Key::ProgressBytesRate,
                        format_size(static_cast<std::uint64_t>(
                            std::llround(bytes_per_second))));
}

} // namespace

ProgressDisplay::~ProgressDisplay() {
    finish();
}

void ProgressDisplay::clear_line() noexcept {
    if (rendered_width_ == 0) {
        return;
    }
    if (terminal_.ansi) {
        std::fputs("\r\x1b[2K", stdout);
        if (rendered_detail_) {
            std::fputs("\x1b[1A\r\x1b[2K", stdout);
        }
    } else {
        std::fputc('\r', stdout);
        const auto columns = platform::terminal_width(terminal_);
        const auto width =
            std::min(rendered_width_, columns > 0 ? columns - 1 : 0);
        for (std::size_t i = 0; i < width; ++i) {
            std::fputc(' ', stdout);
        }
        std::fputc('\r', stdout);
    }
    rendered_width_ = 0;
    rendered_detail_ = false;
}

void ProgressDisplay::render_line(std::string_view line,
                                  std::string_view detail) {
    const auto width = platform::terminal_width(terminal_) - 1U;
    clear_line();
    if (!detail.empty() && terminal_.ansi && width > 0) {
        std::print("{}\n{}",
                   platform::fit_terminal_text(line, width),
                   platform::fit_terminal_text(detail, width));
        rendered_detail_ = true;
    } else if (!detail.empty()) {
        const auto combined = std::format("{} | {}", line, detail);
        std::print("{}", platform::fit_terminal_text(combined, width));
    } else {
        std::print("{}", platform::fit_terminal_text(line, width));
    }
    rendered_width_ = width;
    rendered_last_ = true;
    std::fflush(stdout);
}

void ProgressDisplay::heartbeat() noexcept try {
    const auto now = std::chrono::steady_clock::now();
    if (terminal_.interactive && last_event_ &&
        now - last_render_ >= std::chrono::seconds(1)) {
        render_event(*last_event_, last_extra_);
    }
} catch (...) {
}

std::string ProgressDisplay::applying_line() const {
    const auto applied = apply_progress_->applied_items.value_or(0);
    const auto total = apply_progress_->total_items;
    return (terminal_.interactive
                ? std::string{"      "}
                : std::string{i18n::tr(i18n::Key::SyncStageApplying)} + " | ") +
           i18n::format(i18n::Key::SyncApplyingProgress,
                        applied,
                        total,
                        progress_percent(applied, total));
}

void ProgressDisplay::flush_transfer(TransferMetricsState& state) noexcept try {
    if (!terminal_.interactive || !state.active || state.completed_reported ||
        !state.last_event ||
        (state.last_event->bytes == 0 && state.last_event->objects == 0)) {
        state = {};
        return;
    }
    render_event(*state.last_event, state.last_extra, true);
    if (rendered_width_ != 0) {
        std::fputc('\n', stdout);
        rendered_width_ = 0;
        rendered_detail_ = false;
    }
    const auto elapsed = std::chrono::duration<double>(
                             std::chrono::steady_clock::now() - state.started)
                             .count();
    const auto total_bytes = state.last_event->bytes;
    if (total_bytes > 0 && elapsed > 0.0) {
        const double avg = static_cast<double>(total_bytes) / elapsed;
        if (avg > 0.0 && avg < 1e18) {
            const double min_rate =
                state.min_rate ? std::min(*state.min_rate, avg) : avg;
            const double max_rate =
                state.max_rate ? std::max(*state.max_rate, avg) : avg;
            std::println("{}{}",
                         indented_ ? "      " : "",
                         i18n::format(i18n::Key::ProgressSpeedSummary,
                                      format_bytes_rate(avg),
                                      format_bytes_rate(min_rate),
                                      format_bytes_rate(max_rate)));
        }
    }
    std::fflush(stdout);
    state.completed_reported = true;
} catch (...) {
    state = {};
    clear_line();
}

void ProgressDisplay::finish(bool keep) noexcept try {
    if (!keep) {
        upload_state_ = {};
        download_state_ = {};
        last_event_.reset();
        last_extra_.clear();
        rendered_last_ = true;
    } else if (terminal_.interactive) {
        if (in_applying_ && !full_) {
            const bool had_upload = upload_state_.active &&
                                    !upload_state_.completed_reported &&
                                    (upload_state_.last_bytes > 0 ||
                                     upload_state_.last_objects > 0);
            const bool had_download = download_state_.active &&
                                      !download_state_.completed_reported &&
                                      (download_state_.last_bytes > 0 ||
                                       download_state_.last_objects > 0);
            if (had_upload) {
                flush_transfer(upload_state_);
            }
            if (had_download) {
                flush_transfer(download_state_);
            }
            if (had_upload || had_download) {
                activity_.reset();
                stage_id_ = 0;
                last_event_.reset();
                last_extra_.clear();
                rendered_last_ = true;
                return;
            }
            keep = false;
        } else if (last_event_ && is_byte_transfer(last_event_->activity)) {
            auto& state =
                last_event_->activity == application::Activity::Uploading
                    ? upload_state_
                    : download_state_;
            if (state.active && !state.completed_reported && state.last_event &&
                state.last_event->bytes > 0) {
                flush_transfer(state);
                activity_.reset();
                stage_id_ = 0;
                last_event_.reset();
                last_extra_.clear();
                rendered_last_ = true;
                return;
            }
        } else if (!rendered_last_ && last_event_) {
            render_event(*last_event_, last_extra_, true);
        }
    }
    if (rendered_width_ != 0) {
        if (keep) {
            std::fputc('\n', stdout);
            rendered_width_ = 0;
            rendered_detail_ = false;
        } else {
            clear_line();
        }
    }
    last_event_.reset();
    last_extra_.clear();
    rendered_last_ = true;
    std::fflush(stdout);
} catch (...) {
    upload_state_ = {};
    download_state_ = {};
    last_event_.reset();
    last_extra_.clear();
    rendered_last_ = true;
    clear_line();
}

void ProgressDisplay::render_event(const application::ActivityProgress& event,
                                   std::string_view extra,
                                   bool force_complete) {
    using A = application::Activity;
    using K = i18n::Key;
    const bool show_plan = apply_progress_ && !force_complete;
    const bool show_file = show_plan && !event.item_path.empty();
    const auto label = progress_label(event, show_plan);
    std::string line =
        indented_ && (!show_plan || terminal_.ansi) ? "      " : "";
    line += event.activity == A::Reobserving
                ? i18n::format(label, event.attempt)
                : std::string{i18n::tr(label)};

    const auto add = [&](std::string_view text) {
        line += " | ";
        line += text;
    };
    const auto bytes =
        show_file ? event.item_bytes.value_or(event.bytes) : event.bytes;
    const auto total_bytes = show_file && event.item_bytes
                                 ? event.item_total_bytes
                                 : event.total_bytes;
    const bool scanning =
        event.activity == A::Scanning || event.activity == A::Reobserving;
    if (scanning) {
        add(i18n::format(K::ProgressScan,
                         event.objects,
                         event.total_objects.value_or(0),
                         event.cache_hits,
                         event.files_hashed));
        add(i18n::format(K::ProgressRead, format_size(event.bytes)));
        if (event.observing_remote) {
            add(i18n::tr(K::ProgressRemotePending));
        }
    } else if ((event.objects != 0 || event.total_objects) &&
               (!show_plan || (!show_file && (full_ || !total_bytes)))) {
        add(event.total_objects
                ? progress_count(
                      event.activity, event.objects, *event.total_objects)
                : format_plural(
                      event.objects, K::ProgressObject, K::ProgressObjects));
    }
    if (event.staged_bytes) {
        if (event.bytes != 0 || *event.staged_bytes != 0) {
            add(i18n::format(K::ProgressStaged,
                             format_size(event.bytes),
                             format_size(*event.staged_bytes)));
        }
    } else if (!scanning && (bytes != 0 || total_bytes)) {
        add(total_bytes ? i18n::format(K::ProgressFraction,
                                       format_size(bytes),
                                       format_size(*total_bytes))
                        : format_size(bytes));
    }
    const bool object_rate = event.activity == A::Removing;
    const auto value = object_rate ? event.objects : bytes;
    const auto total = object_rate ? event.total_objects : total_bytes;
    if (!scanning) {
        if (!show_file && event.total_objects && *event.total_objects > 0 &&
            (event.activity == A::Auditing || !total_bytes)) {
            add(i18n::format(
                K::ProgressPercent,
                progress_percent(event.objects, *event.total_objects)));
        } else if (total && *total > 0) {
            add(i18n::format(K::ProgressPercent,
                             progress_percent(value, *total)));
        }
    }
    if (show_file) {
        add(remote_text(platform::path::to_utf8(event.item_path)));
    }
    if (full_ && event.bytes_reused != 0) {
        add(i18n::format(K::ProgressReused, format_size(event.bytes_reused)));
    }
    const auto now = std::chrono::steady_clock::now();
    double display_rate = show_file && event.item_bytes ? 0.0 : rate_;
    if (force_complete && is_byte_transfer(event.activity) && event.bytes > 0) {
        const auto& state =
            event.activity == A::Uploading ? upload_state_ : download_state_;
        const auto elapsed =
            std::chrono::duration<double>(now - state.started).count();
        if (elapsed > 0.0) {
            display_rate = static_cast<double>(event.bytes) / elapsed;
        }
    }
    bool has_eta = false;
    if (display_rate > 0 && display_rate < 1e18 &&
        (force_complete || now - started_ >= std::chrono::milliseconds(500))) {
        add(object_rate ? i18n::format(K::ProgressObjectsRate,
                                       std::format("{:.1f}", display_rate))
                        : format_bytes_rate(display_rate));
        if (!force_complete && total && *total > value && !scanning &&
            event.activity != A::Auditing) {
            const auto eta =
                std::ceil(static_cast<double>(*total - value) / display_rate);
            if (eta <= 86400.0 * 365.0) {
                has_eta = true;
                add(i18n::format(K::ProgressEta,
                                 format_eta(static_cast<std::uint64_t>(eta))));
            }
        }
    }
    if (!force_complete && !has_eta) {
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(now - started_)
                .count();
        if (elapsed > 0) {
            add(i18n::format(K::ProgressElapsed,
                             format_eta(static_cast<std::uint64_t>(elapsed))));
        }
    }
    if (!extra.empty()) {
        add(extra);
    }

    if (show_plan) {
        render_line(applying_line(), line);
    } else {
        render_line(line);
    }
}

void ProgressDisplay::show(const application::ActivityProgress& raw_event,
                           std::string_view extra) {
    using A = application::Activity;
    using K = i18n::Key;

    if (!terminal_.interactive) {
        const bool activity_changed = activity_ != raw_event.activity;
        const bool transition =
            activity_changed || stage_id_ != raw_event.stage_id;
        if (transition) {
            plain_milestone_.reset();
        }
        activity_ = raw_event.activity;
        stage_id_ = raw_event.stage_id;
        if (apply_progress_ && !full_) {
            return;
        }
        const auto label = progress_label(raw_event);
        if (raw_event.total_objects && *raw_event.total_objects > 0 &&
            raw_event.activity != A::Scanning &&
            raw_event.activity != A::Reobserving) {
            const auto total = *raw_event.total_objects;
            const auto done = std::min(raw_event.objects, total);
            const auto percent = progress_percent(done, total);
            if (plain_milestone_ != percent / 10) {
                plain_milestone_ = percent / 10;
                std::println("{} | {} | {}",
                             i18n::tr(label),
                             progress_count(raw_event.activity, done, total),
                             i18n::format(K::ProgressPercent, percent));
                std::fflush(stdout);
            }
        } else if ((activity_changed ||
                    (transition && raw_event.activity == A::Reobserving)) &&
                   raw_event.activity != A::Scanning &&
                   raw_event.activity != A::Removing) {
            std::println("{}",
                         raw_event.activity == A::Reobserving
                             ? i18n::format(label, raw_event.attempt)
                             : std::string{i18n::tr(label)});
            std::fflush(stdout);
        }
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    application::ActivityProgress event = raw_event;

    if (is_byte_transfer(raw_event.activity)) {
        auto& state = raw_event.activity == A::Uploading ? upload_state_
                                                         : download_state_;
        if (in_applying_ && !full_) {
            auto& other = raw_event.activity == A::Uploading ? download_state_
                                                             : upload_state_;
            if (other.active && !other.completed_reported &&
                (other.last_bytes > 0 || other.last_objects > 0)) {
                flush_transfer(other);
            }
            if (!state.active || state.completed_reported) {
                state = {};
                state.active = true;
                state.last_stage_id = raw_event.stage_id;
                state.started = now;
                state.last_sample = now;
            } else if (state.last_stage_id != raw_event.stage_id) {
                state.base_objects += state.last_objects;
                state.base_total_objects += state.last_total_objects;
                state.base_bytes += state.last_bytes;
                state.base_total_bytes += state.last_total_bytes;
                state.last_objects = 0;
                state.last_total_objects = 0;
                state.last_bytes = 0;
                state.last_total_bytes = 0;
                state.last_stage_id = raw_event.stage_id;
                state.last_sample_bytes = state.base_bytes;
                state.last_sample = now;
                if (apply_progress_) {
                    state.rate = 0;
                }
            }
            state.last_objects = raw_event.objects;
            state.last_total_objects =
                raw_event.total_objects.value_or(raw_event.objects);
            state.last_bytes = raw_event.bytes;
            state.last_total_bytes =
                raw_event.total_bytes.value_or(raw_event.bytes);

            event.objects = state.base_objects + raw_event.objects;
            if (raw_event.total_objects) {
                event.total_objects =
                    state.base_total_objects + *raw_event.total_objects;
            } else if (state.base_total_objects > 0) {
                event.total_objects =
                    state.base_total_objects + raw_event.objects;
            }
            event.bytes = state.base_bytes + raw_event.bytes;
            if (raw_event.total_bytes) {
                event.total_bytes =
                    state.base_total_bytes + *raw_event.total_bytes;
            } else if (state.base_total_bytes > 0) {
                event.total_bytes = state.base_total_bytes + raw_event.bytes;
            }
        } else {
            if (!state.active || state.last_stage_id != raw_event.stage_id) {
                state = {};
                state.active = true;
                state.last_stage_id = raw_event.stage_id;
                state.started = now;
                state.last_sample = now;
            }
            state.last_objects = raw_event.objects;
            state.last_total_objects =
                raw_event.total_objects.value_or(raw_event.objects);
            state.last_bytes = raw_event.bytes;
            state.last_total_bytes =
                raw_event.total_bytes.value_or(raw_event.bytes);
        }

        const auto dt_sample =
            std::chrono::duration<double>(now - state.last_sample).count();
        if (dt_sample >= 0.20 && event.bytes > state.last_sample_bytes) {
            const double inst =
                static_cast<double>(event.bytes - state.last_sample_bytes) /
                dt_sample;
            state.rate =
                state.rate <= 0.0
                    ? inst
                    : state.rate + (inst - state.rate) *
                                       (1.0 - std::exp(-dt_sample / 2.5));
            state.last_sample = now;
            state.last_sample_bytes = event.bytes;
            if (state.rate > 0.0 && state.rate < 1e18 &&
                now - state.started >= std::chrono::milliseconds(400)) {
                state.min_rate = state.min_rate
                                     ? std::min(*state.min_rate, state.rate)
                                     : state.rate;
                state.max_rate = state.max_rate
                                     ? std::max(*state.max_rate, state.rate)
                                     : state.rate;
            }
        }
        state.last_event = event;
        state.last_extra = std::string{extra};
    } else if (!in_applying_ && download_state_.active &&
               !download_state_.completed_reported &&
               download_state_.last_bytes > 0) {
        flush_transfer(download_state_);
    }

    // Only the retained summary uses totals accumulated across transfer
    // batches.
    if (apply_progress_) {
        event = raw_event;
    }
    const bool transition =
        activity_ != event.activity || stage_id_ != event.stage_id;
    const bool object_rate = event.activity == A::Removing;
    const auto value = object_rate ? event.objects : event.bytes;
    const auto total = object_rate ? event.total_objects : event.total_bytes;
    const bool has_object_total =
        event.total_objects && *event.total_objects > 0;
    const bool complete =
        (has_object_total || (total && *total > 0)) &&
        (!has_object_total || event.objects >= *event.total_objects) &&
        (!total || value >= *total);

    if (transition) {
        if (full_ && activity_) {
            finish(true);
        } else {
            clear_line();
        }
        activity_ = event.activity;
        stage_id_ = event.stage_id;
        started_ = now;
        last_render_ = now;
        last_value_ = value;
        last_objects_ = event.objects;
        rate_ = is_byte_transfer(event.activity)
                    ? (event.activity == A::Uploading ? upload_state_.rate
                                                      : download_state_.rate)
                    : 0.0;
        was_complete_ = false;
        last_event_ = event;
        last_extra_ = std::string{extra};
        rendered_last_ = false;
        render_event(event, extra);
        return;
    }

    const auto dt = std::chrono::duration<double>(now - last_render_).count();
    if (is_byte_transfer(event.activity)) {
        rate_ = event.activity == A::Uploading ? upload_state_.rate
                                               : download_state_.rate;
    } else if (dt > 0 && value >= last_value_) {
        const auto instantaneous =
            static_cast<double>(value - last_value_) / dt;
        rate_ = rate_ <= 0.0 ? instantaneous
                             : rate_ + (instantaneous - rate_) *
                                           (1.0 - std::exp(-dt / 2.5));
    }

    const bool objects_advanced = event.objects != last_objects_;
    last_event_ = event;
    last_extra_ = std::string{extra};
    rendered_last_ = false;

    if (now - last_render_ < std::chrono::milliseconds(200) &&
        !(complete && (!was_complete_ || objects_advanced))) {
        return;
    }

    render_event(event, extra);
    last_render_ = now;
    last_value_ = value;
    last_objects_ = event.objects;
    was_complete_ = complete;
}

void ProgressDisplay::update(const application::ExecutionProgress& progress,
                             application::Operation operation) {
    std::visit(
        [&](const auto& event) {
            using T = std::decay_t<decltype(event)>;
            using A = application::Activity;
            if constexpr (std::is_same_v<T, application::ActivityProgress>) {
                show(event);
            } else if constexpr (std::is_same_v<T, application::SyncProgress>) {
                if (event.stage == application::SyncStage::Applying &&
                    event.applied_items && apply_progress_ &&
                    event.total_items == apply_progress_->total_items) {
                    const auto previous = progress_percent(
                        apply_progress_->applied_items.value_or(0),
                        event.total_items);
                    apply_progress_->applied_items = event.applied_items;
                    if (terminal_.interactive) {
                        if (last_event_) {
                            render_event(*last_event_, last_extra_);
                        } else {
                            render_line(applying_line());
                        }
                    } else if (previous / 10 !=
                               progress_percent(*event.applied_items,
                                                event.total_items) /
                                   10) {
                        std::println("{}", applying_line());
                    }
                    return;
                }
                const bool was_applying = in_applying_;
                const bool keep_stage =
                    full_ || (was_applying &&
                              event.stage != application::SyncStage::Applying);
                if (apply_progress_) {
                    clear_line();
                }
                if (terminal_.interactive && apply_progress_ &&
                    apply_progress_->applied_items ==
                        apply_progress_->total_items) {
                    std::println("{}", applying_line());
                }
                finish(keep_stage);
                started_ = std::chrono::steady_clock::now();
                apply_progress_.reset();
                if (was_applying &&
                    event.stage != application::SyncStage::Applying) {
                    upload_state_ = {};
                    download_state_ = {};
                }
                in_applying_ = event.stage == application::SyncStage::Applying;
                indented_ = true;
                activity_.reset();
                stage_id_ = 0;
                if (in_applying_ && event.total_items > 0) {
                    apply_progress_ = event;
                    if (terminal_.interactive) {
                        present(event, operation);
                        render_line(applying_line());
                    } else {
                        std::println("{}", applying_line());
                    }
                } else {
                    present(event, operation);
                }
            } else if constexpr (std::is_same_v<T, application::FsckProgress>) {
                if (fsck_.last_stage != event.stage) {
                    const bool keep_fsck =
                        fsck_.last_stage ==
                            application::FsckStage::AuditingContent ||
                        full_;
                    finish(keep_fsck);
                    started_ = std::chrono::steady_clock::now();
                    indented_ = true;
                    activity_.reset();
                    stage_id_ = 0;
                    if (terminal_.interactive) {
                        auto stage = event;
                        stage.total_objects.reset();
                        present(stage, fsck_);
                    }
                }
                if (!terminal_.interactive || event.total_objects == 0) {
                    present(event, fsck_);
                } else if (event.stage ==
                               application::FsckStage::AuditingContent &&
                           event.total_objects) {
                    using K = i18n::Key;
                    auto detail =
                        i18n::format(K::ProgressFsckCounts,
                                     event.physical_objects_downloaded,
                                     event.files_reassembled);
                    if (event.completed_plaintext_bytes &&
                        event.total_plaintext_bytes) {
                        detail = i18n::format(
                                     K::ProgressVerifiedBytes,
                                     i18n::format(
                                         K::ProgressFraction,
                                         format_size(
                                             *event.completed_plaintext_bytes),
                                         format_size(
                                             *event.total_plaintext_bytes))) +
                                 " | " + detail;
                    }
                    show({.activity = A::Auditing,
                          .bytes = event.wire_download_bytes,
                          .total_bytes = event.total_wire_bytes,
                          .objects = event.completed_objects,
                          .total_objects = *event.total_objects},
                         detail);
                }
            } else {
                if (gc_.last_stage != event.stage) {
                    finish(gc_.last_stage ==
                           application::GarbageCollectStage::Applying);
                    started_ = std::chrono::steady_clock::now();
                    indented_ = true;
                    activity_.reset();
                    stage_id_ = 0;
                }
                present(event, gc_);
                if (event.stage == application::GarbageCollectStage::Applying &&
                    event.candidate_count && *event.candidate_count > 0) {
                    show({.activity = A::Removing,
                          .objects = event.removed_objects,
                          .total_objects = *event.candidate_count});
                }
            }
        },
        progress);
    std::fflush(stdout);
}

int present(const application::Response& response, bool full) {
    const auto op = response.operation;
    return std::visit(
        [&](const auto& data) -> int {
            using T = std::decay_t<decltype(data)>;
            using Op = application::Operation;
            if constexpr (std::is_same_v<T, application::SyncCompleted>) {
                if (op != Op::Sync) {
                    return 1;
                }
                int exit_code = 0;
                if (data.partial) {
                    render_pending_paths(data.pending_paths, full);
                    exit_code = 2;
                } else {
                    print_ok_line(i18n::tr(i18n::Key::SyncCompleted));
                }
                if (data.physical_objects_uploaded ||
                    data.physical_objects_downloaded ||
                    data.local_delta_reused_bytes) {
                    i18n::println(
                        i18n::Key::ProgressWireSummary,
                        format_size(data.wire_upload_bytes),
                        format_plural(data.physical_objects_uploaded,
                                      i18n::Key::ProgressObject,
                                      i18n::Key::ProgressObjects),
                        format_size(data.wire_download_bytes),
                        format_plural(data.physical_objects_downloaded,
                                      i18n::Key::ProgressObject,
                                      i18n::Key::ProgressObjects),
                        format_size(data.local_delta_reused_bytes));
                }
                if (data.trusted_content_reused > 0) {
                    std::println(
                        "{}",
                        i18n::format(i18n::Key::SyncTrustedContentWarning,
                                     data.trusted_content_reused));
                }
                if (response.inventory_audit) {
                    exit_code = std::max(
                        exit_code,
                        render_inventory_audit(*response.inventory_audit));
                }
                return exit_code;
            } else if constexpr (std::is_same_v<T, application::PlanReport>) {
                if (op != Op::Preview && op != Op::Status) {
                    return 1;
                }
                render_plan_report(data, full);
                if (op == Op::Preview) {
                    i18n::println(i18n::Key::PreviewCompleted);
                }
                return data.pending_paths.empty() ? 0 : 2;
            } else if constexpr (std::is_same_v<T,
                                                application::FsckCompleted>) {
                if (op != Op::Fsck) {
                    return 1;
                }
                print_ok_line(i18n::tr(i18n::Key::ErrorFsckClean));
                std::println("{}",
                             format_plural(data.checked_objects,
                                           i18n::Key::FsckSummarySingular,
                                           i18n::Key::FsckSummaryPlural));
                if (data.checked_plaintext_bytes.has_value()) {
                    std::println(
                        "{}",
                        i18n::format(
                            i18n::Key::FsckSummaryBytes,
                            format_size(*data.checked_plaintext_bytes)));
                }
                if (data.wire_download_bytes ||
                    data.physical_objects_downloaded ||
                    data.files_reassembled) {
                    i18n::println(
                        i18n::Key::FsckWireSummary,
                        format_size(data.wire_download_bytes),
                        format_plural(data.physical_objects_downloaded,
                                      i18n::Key::ProgressObject,
                                      i18n::Key::ProgressObjects),
                        data.files_reassembled);
                }
                return 0;
            } else if constexpr (
                std::is_same_v<T, application::ManualWriterRemovalCompleted>) {
                if (op != Op::RemoveWriter) {
                    return 1;
                }
                print_ok_line(i18n::format(
                    i18n::Key::ManualWriterRemovalCompleted, data.identifier));
                return 0;
            } else if constexpr (
                std::is_same_v<T, application::ManualBarrierRemovalCompleted>) {
                if (op != Op::RemoveBarrier) {
                    return 1;
                }
                print_ok_line(
                    data.outcome == application::BarrierRemovalOutcome::Removed
                        ? i18n::format(i18n::Key::ManualBarrierRemovalCompleted,
                                       data.identifier)
                        : std::string{
                              i18n::tr(i18n::Key::ManualBarrierRemovalAbsent)});
                if (data.active_writers_count > 0) {
                    std::println(
                        "{} {}",
                        i18n::tr(i18n::Key::LabelWarning),
                        i18n::format(
                            i18n::Key::ManualBarrierRemovalWritersRemain,
                            data.active_writers_count));
                }
                return 0;
            } else if constexpr (std::is_same_v<
                                     T,
                                     application::GarbageCollectCompleted>) {
                if (op != Op::GarbageCollect) {
                    return 1;
                }
                if (data.analysis_only) {
                    const auto header =
                        format_plural(data.candidate_objects,
                                      i18n::Key::GcWarningHeaderSingular,
                                      i18n::Key::GcWarningHeaderPlural);
                    const std::string indent(
                        i18n::tr(i18n::Key::LabelWarning).size() + 1, ' ');
                    print_status_line(
                        style::yellow, i18n::Key::LabelWarning, header);
                    std::println(
                        "{}{}", indent, i18n::tr(i18n::Key::GcWarningDetail1));
                    std::println(
                        "{}{}", indent, i18n::tr(i18n::Key::GcWarningDetail2));
                    return 0;
                }
                print_ok_line(i18n::tr(i18n::Key::GcCompleted));
                auto metrics =
                    i18n::format(i18n::Key::GcSummary, data.candidate_objects) +
                    " " +
                    i18n::format(i18n::Key::GcConfirmedRemovals,
                                 data.removed_objects);
                const auto seconds =
                    std::chrono::duration<double>(data.removal_elapsed).count();
                if (data.removed_objects > 0 && seconds > 0.0) {
                    metrics +=
                        " | " +
                        i18n::format(i18n::Key::ProgressObjectsRate,
                                     std::format("{:.1f}",
                                                 static_cast<double>(
                                                     data.removed_objects) /
                                                     seconds));
                }
                std::println("     {}", metrics);
                return 0;
            } else if constexpr (std::is_same_v<
                                     T,
                                     application::ResolveMissingCompleted>) {
                if (op != Op::ResolveMissing) {
                    return 1;
                }
                if (data.resolved_count > 0) {
                    print_ok_line(
                        format_plural(data.resolved_count,
                                      i18n::Key::ResolveMissingSingular,
                                      i18n::Key::ResolveMissingPlural));
                } else {
                    i18n::println(i18n::Key::ResolveMissingNone);
                }
                return 0;
            } else {
                return 1;
            }
        },
        response.data);
}

int present(const application::InspectionResponse& response) {
    return std::visit(
        [&](const auto& report) -> int {
            if (inspection_op_matches(response)) {
                return present_remote_report(report);
            }
            print_status_line(style::red,
                              i18n::Key::LabelError,
                              i18n::tr(i18n::Key::ErrorInconsistentInspection));
            return 1;
        },
        response.payload);
}

namespace {

std::string sanitize_error_detail(std::string_view detail) {
    std::string result = sanitize_terminal_text(detail);
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

    using C = application::ErrorCode;
    static constexpr std::array<std::pair<C, i18n::Key>, 8> kErrorFormats{{
        {C::PlanFailure, i18n::Key::ErrorPlanCalculation},
        {C::FsckFailure, i18n::Key::ErrorFsckFailed},
        {C::GarbageCollectionFailure, i18n::Key::ErrorGcCancelled},
        {C::WriterRemovalFailure, i18n::Key::ErrorWriterRemovalFailed},
        {C::BarrierRemovalFailure, i18n::Key::ErrorBarrierRemovalFailed},
        {C::InventoryAuditFailure, i18n::Key::ErrorInventoryAuditFailed},
        {C::SynchronizationFailure, i18n::Key::ErrorSyncFailed},
        {C::RecoveryFailure, i18n::Key::ErrorSyncFailed},
    }};
    if (error.code == C::FsckFailure) {
        i18n::println(i18n::Key::ErrorFsckAuditing);
    }
    const auto found = std::ranges::find(
        kErrorFormats, error.code, &std::pair<C, i18n::Key>::first);
    const auto safe_detail = sanitize_terminal_text(error.detail);
    print_error_line(found != kErrorFormats.end()
                         ? i18n::format(found->second, safe_detail)
                         : safe_detail);

    if (error.code == C::BarrierRemovalFailure && error.barrier_removal) {
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
                 i18n::Key::BarrierRemovalStageVerifyingPhysicalIdentity},
                {Stg::Removing, i18n::Key::BarrierRemovalStageRemoving},
                {Stg::ConfirmingAbsence,
                 i18n::Key::BarrierRemovalStageConfirmingAbsence},
            }};
        static constexpr std::array<std::pair<Mst, i18n::Key>, 3>
            kMutationStates{{
                {Mst::NotAttempted,
                 i18n::Key::BarrierRemovalMutationNotAttempted},
                {Mst::Confirmed, i18n::Key::BarrierRemovalMutationConfirmed},
                {Mst::Uncertain, i18n::Key::BarrierRemovalMutationUncertain},
            }};
        std::println("  {}: {}",
                     i18n::tr(i18n::Key::LabelStage),
                     enum_tr(br.stage,
                             kBarrierStages,
                             i18n::Key::BarrierRemovalStageCheckingPresence));
        std::println("  {}: {}",
                     i18n::tr(i18n::Key::LabelMutationState),
                     enum_tr(br.mutation_state,
                             kMutationStates,
                             i18n::Key::BarrierRemovalMutationNotAttempted));
        if (br.transport_error) {
            std::println("  {}: {}",
                         i18n::tr(i18n::Key::LabelTransportError),
                         sanitize_terminal_text(
                             transport::describe(*br.transport_error)));
        }
    } else if (error.code == C::InventoryAuditFailure && error.sync_completed) {
        i18n::println(i18n::Key::ErrorInventoryAuditSyncCompleted);
        if (error.sync_completed->partial) {
            render_pending_status(error.sync_completed->pending);
        }
        if (error.sync_completed->published) {
            i18n::println(i18n::Key::ErrorInventoryAuditPublished);
        }
    }
    return 1;
}

int present(const application::InspectionError& error) {
    print_error_line(error.detail);
    if (error.code == application::InspectionErrorCode::HeadSelectionRequired ||
        (error.code == application::InspectionErrorCode::RemoteHeadNotFound &&
         !error.candidate_ids.empty())) {
        i18n::println(i18n::Key::ErrorAvailableHeads);
        for (const auto& id : error.candidate_ids) {
            std::println("  {}", sanitize_terminal_text(id));
        }
        if (error.code ==
            application::InspectionErrorCode::HeadSelectionRequired) {
            i18n::println(i18n::Key::ErrorUseRemoteTreeHead);
        }
    }
    return 1;
}

} // namespace kasumi::cli
