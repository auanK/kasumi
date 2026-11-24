#include "cli/presenter.hpp"

#include "cli/help_topics.hpp"
#include "cli/i18n.hpp"
#include "cli/style.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <format>
#include <map>
#include <print>
#include <set>
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

void print_warning_line(std::string_view message) {
    print_status_line(style::yellow, i18n::Key::LabelWarning, message);
}

void print_error_line(std::string_view message) {
    print_status_line(style::red, i18n::Key::LabelError, message);
}

std::string
format_plural(std::uint64_t count, i18n::Key singular, i18n::Key plural) {
    return count == 1 ? std::string{i18n::tr(singular)}
                      : i18n::format(plural, count);
}

int present_help(std::string_view topic, bool all) {
    for (const auto& [name, key] : help_topics) {
        if (name == topic) {
            std::print("{}{}", i18n::tr(key), i18n::tr(i18n::Key::HelpOptions));
            return 0;
        }
    }
    std::print(
        "{}", i18n::tr(all ? i18n::Key::HelpTextAll : i18n::Key::HelpText));
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

namespace {

std::string join_summary_parts(const std::vector<std::string>& parts) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            out += " | ";
        }
        out += parts[i];
    }
    return out;
}

std::string format_transfer_part(std::string_view arrow,
                                 std::size_t count,
                                 std::uint64_t bytes) {
    return bytes > 0
               ? std::format("{} {} ({})", arrow, count, format_size(bytes))
               : std::format("{} {}", arrow, count);
}

} // namespace

std::string format_compact_summary(const application::SyncCompleted& sync) {
    if (sync.total == 0 && sync.repaired == 0 && !sync.partial) {
        return "Everything in sync";
    }
    std::vector<std::string> parts;
    if (sync.total > 0) {
        parts.push_back(sync.total == 1
                            ? "1 change"
                            : std::format("{} changes", sync.total));
    }
    if (sync.uploaded > 0) {
        parts.push_back(
            format_transfer_part("↑", sync.uploaded, sync.upload_bytes));
    }
    if (sync.downloaded > 0) {
        parts.push_back(
            format_transfer_part("↓", sync.downloaded, sync.download_bytes));
    }
    if (sync.removed > 0) {
        parts.push_back(std::format("- {}", sync.removed));
    }
    if (sync.renamed > 0) {
        parts.push_back(std::format("→ {}", sync.renamed));
    }
    if (sync.copied > 0) {
        parts.push_back(std::format("cp {}", sync.copied));
    }
    if (sync.created_dirs > 0) {
        parts.push_back(sync.created_dirs == 1
                            ? "+1 dir"
                            : std::format("+{} dirs", sync.created_dirs));
    }
    if (sync.removed_dirs > 0) {
        parts.push_back(sync.removed_dirs == 1
                            ? "-1 dir"
                            : std::format("-{} dirs", sync.removed_dirs));
    }
    if (sync.repaired > 0) {
        parts.push_back(std::format("{} repaired", sync.repaired));
    }
    if (sync.partial) {
        parts.push_back(std::format("{} pending", sync.pending));
    }
    return join_summary_parts(parts);
}

std::string format_compact_summary(const application::Response& response) {
    return std::visit(
        [&](const auto& payload) -> std::string {
            using T = std::decay_t<decltype(payload)>;
            if constexpr (std::is_same_v<T, application::SyncCompleted>) {
                std::string summary = format_compact_summary(payload);
                if (response.inventory_audit) {
                    const auto& audit = *response.inventory_audit;
                    if (audit.missing_content + audit.orphan_content +
                            audit.unknown_objects >
                        0) {
                        summary += std::format(
                            " | audit: {} missing, {} orphan, {} unknown",
                            audit.missing_content,
                            audit.orphan_content,
                            audit.unknown_objects);
                    }
                }
                return summary;
            } else if constexpr (std::is_same_v<T, application::PlanReport>) {
                if (payload.items.empty() && payload.pending_paths.empty()) {
                    return "Everything in sync";
                }
                std::vector<std::string> parts;
                if (!payload.items.empty()) {
                    parts.push_back(
                        std::format("{} planned", payload.items.size()));
                }
                if (payload.upload_bytes > 0) {
                    parts.push_back(
                        std::format("↑ {}", format_size(payload.upload_bytes)));
                }
                if (payload.download_bytes > 0) {
                    parts.push_back(std::format(
                        "↓ {}", format_size(payload.download_bytes)));
                }
                if (payload.has_conflicts) {
                    parts.push_back("conflicts");
                }
                if (!payload.pending_paths.empty()) {
                    parts.push_back(std::format("{} pending",
                                                payload.pending_paths.size()));
                }
                return join_summary_parts(parts);
            } else if constexpr (std::is_same_v<T,
                                                application::FsckCompleted>) {
                std::string summary =
                    payload.checked_objects == 1
                        ? "1 object verified"
                        : std::format("{} objects verified",
                                      payload.checked_objects);
                if (payload.checked_plaintext_bytes) {
                    summary += std::format(
                        " ({})", format_size(*payload.checked_plaintext_bytes));
                }
                return summary;
            } else if constexpr (std::is_same_v<
                                     T,
                                     application::GarbageCollectCompleted>) {
                std::string summary;
                if (payload.dry_run) {
                    summary =
                        payload.candidate_objects == 0
                            ? "no eligible candidates"
                            : ((payload.candidate_expired_commits > 0 ||
                                payload.candidate_bytes > 0)
                                   ? std::format(
                                         "{} candidates ({} content, {} "
                                         "variants, {} expired commits, {} "
                                         "activities, {})",
                                         payload.candidate_objects,
                                         payload.candidate_content_objects,
                                         payload.candidate_commit_variants,
                                         payload.candidate_expired_commits,
                                         payload.candidate_activities,
                                         format_size(payload.candidate_bytes))
                                   : std::format(
                                         "{} candidates ({} content, {} "
                                         "commits, {} activities)",
                                         payload.candidate_objects,
                                         payload.candidate_content_objects,
                                         payload.candidate_commit_variants,
                                         payload.candidate_activities));
                } else if (payload.removed_objects == 0) {
                    summary = "no eligible objects removed";
                } else {
                    summary = payload.removed_objects == 1
                                  ? "1 object removed"
                                  : std::format("{} objects removed",
                                                payload.removed_objects);
                    if (payload.removed_bytes > 0) {
                        summary += std::format(
                            " ({})", format_size(payload.removed_bytes));
                    }
                }
                if (payload.deferred_recent_objects > 0) {
                    summary += std::format(" ({} deferred)",
                                           payload.deferred_recent_objects);
                }
                return summary;
            } else if constexpr (std::is_same_v<T,
                                                application::RepackCompleted>) {
                if (!payload.actionable) {
                    return "nothing to repack";
                }
                return std::format(
                    "{}{} {} ({}) into {} {}",
                    payload.dry_run ? "plan: " : "repacked ",
                    payload.repacked_blobs,
                    payload.repacked_blobs == 1 ? "blob" : "blobs",
                    format_size(payload.repacked_plaintext_bytes),
                    payload.new_packs,
                    payload.new_packs == 1 ? "pack" : "packs");
            } else if constexpr (std::is_same_v<
                                     T,
                                     application::ResolveMissingCompleted>) {
                if (payload.resolved_paths.empty()) {
                    return "no pending missing paths";
                }
                if (payload.dry_run) {
                    return std::format(
                        "{} pending {} eligible",
                        payload.resolved_paths.size(),
                        payload.resolved_paths.size() == 1 ? "path" : "paths");
                }
                return std::format("{} missing {} resolved",
                                   payload.resolved_count,
                                   payload.resolved_count == 1 ? "path"
                                                               : "paths");
            } else if constexpr (
                std::is_same_v<T, application::ManualWriterRemovalCompleted>) {
                return "writer removed";
            } else if constexpr (
                std::is_same_v<T, application::ManualBarrierRemovalCompleted>) {
                return payload.outcome ==
                               application::BarrierRemovalOutcome::Removed
                           ? "barrier removed"
                           : "barrier already absent";
            } else {
                return "ok";
            }
        },
        response.data);
}

std::string
format_compact_summary(const application::DiagnosticsReport& report) {
    const std::size_t n = report.profiles.size();
    const std::string_view rclone_state =
        report.rclone.found ? (report.rclone.version.empty()
                                   ? std::string_view{"found"}
                                   : std::string_view{report.rclone.version})
                            : std::string_view{"missing"};
    return std::format("{} {}, overall={}, rclone={}",
                       n,
                       n == 1 ? "profile" : "profiles",
                       report.overall_ok ? "ok" : "issues",
                       rclone_state);
}

std::string
format_compact_summary(const application::LocalConflictsReport& report) {
    if (report.total_artifacts == 0) {
        return "0 conflicts";
    }
    return std::format("{} conflict(s) across {} path(s)",
                       report.total_artifacts,
                       report.groups.size());
}

std::string
format_compact_summary(const application::ResolveConflictReport& report) {
    const std::string_view kept =
        report.selected_artifact ? std::string_view{*report.selected_artifact}
                                 : std::string_view{"canonical"};
    if (report.dry_run) {
        return std::format("dry-run: keep={} ({} artifact(s))",
                           kept,
                           report.removed_artifacts.size());
    }
    return std::format("resolved {} (kept={}, removed={})",
                       report.canonical_path,
                       kept,
                       report.removed_artifacts.size());
}

std::string
format_compact_summary(const application::InspectionResponse& response) {
    if (const auto* s =
            std::get_if<application::RemoteSummaryReport>(&response.payload)) {
        std::string out = std::format("height={}, heads={}, commits={}",
                                      s->observed_height,
                                      s->logical_head_count,
                                      s->reachable_commit_count);
        if (s->has_conflicts) {
            out += ", conflicts";
        }
        if (s->missing_content_count > 0) {
            out += std::format(", missing={}", s->missing_content_count);
        }
        return out;
    }
    if (const auto* l =
            std::get_if<application::RemoteLogReport>(&response.payload)) {
        return std::format("{} entry/entries (height={})",
                           l->entries.size(),
                           l->observed_height);
    }
    if (const auto* r =
            std::get_if<application::RemoteRestoreReport>(&response.payload)) {
        return std::format("{}{} file(s) ({})",
                           r->dry_run ? "dry-run: " : "",
                           r->file_count,
                           format_size(r->total_bytes));
    }
    return "ok";
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

namespace {

template <typename Range, typename Extract>
std::set<std::string> colliding_machine_names(const Range& items,
                                              Extract&& extract) {
    std::map<std::string, std::set<std::string>> ids_by_name;
    for (const auto& item : items) {
        const auto [name, id] = extract(item);
        if (!name.empty() && !id.empty()) {
            ids_by_name[std::string{name}].insert(std::string{id});
        }
    }
    std::set<std::string> colliding;
    for (const auto& [name, ids] : ids_by_name) {
        if (ids.size() > 1) {
            colliding.insert(name);
        }
    }
    return colliding;
}

void present_commit_authorship(
    const std::optional<application::RemoteCommitAuthorship>& authorship,
    const std::set<std::string>& colliding_names,
    bool always_show_id) {
    if (!authorship) {
        i18n::println(i18n::Key::FieldOrigin,
                      i18n::tr(i18n::Key::LabelUnknown));
        i18n::println(i18n::Key::FieldMachine,
                      i18n::tr(i18n::Key::LabelUnknown));
        return;
    }
    i18n::println(
        i18n::Key::FieldOrigin,
        commit_origin_label(static_cast<std::uint8_t>(authorship->operation)));
    const bool show_id =
        always_show_id || colliding_names.contains(authorship->machine_name);
    i18n::println(i18n::Key::FieldMachine,
                  format_machine_label(authorship->machine_name,
                                       authorship->machine_id_hex,
                                       show_id,
                                       false));
}

template <typename Item>
void present_activity_item(const Item& item,
                           const std::set<std::string>& colliding_names,
                           bool full) {
    const auto op_raw = static_cast<std::uint8_t>(item.operation);
    const auto out_raw = static_cast<std::uint8_t>(item.outcome);
    const auto ts = platform::clock::format_local_timestamp(item.finished_at);
    const auto op = activity_operation_label(op_raw);
    const auto outcome = activity_outcome_label(out_raw);
    const bool show_id = full || colliding_names.contains(item.machine_name);
    const auto machine = format_machine_label(
        item.machine_name, item.machine_id_hex, show_id, full);
    const auto metrics = format_activity_metrics(op_raw,
                                                 item.metric_primary,
                                                 item.metric_secondary,
                                                 item.metric_bytes,
                                                 item.flags);
    const auto flags = format_activity_flags(item.flags);
    std::string extra;
    if (!metrics.empty()) {
        extra += metrics;
    }
    if (!flags.empty()) {
        if (!extra.empty()) {
            extra += ", ";
        }
        extra += flags;
    }
    if (full) {
        const auto dur =
            format_duration(std::chrono::milliseconds(item.duration_ms));
        if (extra.empty()) {
            std::println(
                "  {} | {:<17} | {} | {} | {}", ts, op, outcome, dur, machine);
        } else {
            std::println("  {} | {:<17} | {} | {} | {} ({})",
                         ts,
                         op,
                         outcome,
                         dur,
                         machine,
                         extra);
        }
        if (!item.stage.empty() || !item.detail.empty()) {
            std::string note;
            if (!item.stage.empty()) {
                note = sanitize_terminal_text(item.stage);
            }
            if (!item.detail.empty()) {
                if (!note.empty()) {
                    note += ": ";
                }
                note += sanitize_terminal_text(item.detail);
            }
            std::println("    {}", note);
        }
    } else {
        if (item.outcome != application::RemoteActivityOutcome::Succeeded &&
            !item.stage.empty()) {
            if (!extra.empty()) {
                extra += ", ";
            }
            extra += sanitize_terminal_text(item.stage);
        }
        if (extra.empty()) {
            std::println("  {:<17} {} | {} | {}", op, ts, outcome, machine);
        } else {
            std::println(
                "  {:<17} {} | {} | {} ({})", op, ts, outcome, machine, extra);
        }
    }
}

} // namespace

template <typename Report>
int present_remote_report(const Report& report) = delete;

int present_remote_report(const application::RemoteHeadsReport& report) {
    if (report.heads.empty()) {
        i18n::println(i18n::Key::RemoteHeadsNone);
        return 0;
    }

    const auto colliding = colliding_machine_names(
        report.heads,
        [](const application::RemoteHeadInfo& h)
            -> std::pair<std::string_view, std::string_view> {
            if (!h.authorship) {
                return {};
            }
            return {h.authorship->machine_name, h.authorship->machine_id_hex};
        });

    i18n::println(i18n::Key::RemoteHeadsHeader, report.heads.size());
    render_indexed(report.heads, [&](const auto& head) {
        i18n::println(i18n::Key::FieldCommit, remote_text(head.commit_id));
        i18n::println(i18n::Key::FieldHeight, head.height);
        i18n::println(i18n::Key::FieldCreatedAt,
                      platform::clock::format_local_timestamp(head.created_at));
        present_commit_authorship(head.authorship, colliding, false);
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

    const auto colliding = colliding_machine_names(
        report.commits,
        [](const application::RemoteCommitInfo& c)
            -> std::pair<std::string_view, std::string_view> {
            if (!c.authorship) {
                return {};
            }
            return {c.authorship->machine_name, c.authorship->machine_id_hex};
        });

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
        i18n::println(
            i18n::Key::FieldCreatedAt,
            platform::clock::format_local_timestamp(commit.created_at));
        present_commit_authorship(commit.authorship, colliding, false);
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

int present_remote_report(const application::RemoteSummaryReport& report,
                          bool full = false) {
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
    if (report.invalid_activity_count > 0) {
        i18n::println(i18n::Key::FieldInvalidActivities,
                      report.invalid_activity_count);
    }
    if (report.recent_activities.empty()) {
        i18n::println(i18n::Key::RemoteSummaryNoActivity);
        return 0;
    }

    std::vector<const application::RemoteActivityInfo*> sorted;
    sorted.reserve(report.recent_activities.size());
    for (const auto& item : report.recent_activities) {
        sorted.push_back(&item);
    }
    std::ranges::sort(sorted, [](const auto* a, const auto* b) {
        if (a->finished_at != b->finished_at) {
            return a->finished_at > b->finished_at;
        }
        return a->started_at > b->started_at;
    });
    const auto colliding = colliding_machine_names(
        report.recent_activities,
        [](const application::RemoteActivityInfo& item)
            -> std::pair<std::string_view, std::string_view> {
            return {item.machine_name, item.machine_id_hex};
        });

    std::vector<const application::RemoteActivityInfo*> selected;
    if (full) {
        selected = sorted;
    } else {
        std::set<std::uint8_t> seen_ops;
        for (const auto* item : sorted) {
            const auto op = static_cast<std::uint8_t>(item->operation);
            if (seen_ops.insert(op).second) {
                selected.push_back(item);
            }
        }
    }
    i18n::println(i18n::Key::RemoteSummaryActivityHeader, selected.size());
    for (const auto* item : selected) {
        present_activity_item(*item, colliding, full);
    }
    if (!full && sorted.size() > selected.size()) {
        i18n::println(i18n::Key::RemoteSummaryActivityMoreHint, sorted.size());
    }
    return 0;
}

int present_remote_report(const application::RemoteStatReport& report) {
    i18n::println(i18n::Key::RemoteStatHeader);
    if (report.commit_id) {
        i18n::println(i18n::Key::FieldCommit, remote_text(*report.commit_id));
    } else {
        i18n::println(i18n::Key::RemoteStatView);
    }
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
    i18n::println(i18n::Key::FieldCreatedAt,
                  platform::clock::format_local_timestamp(commit.created_at));
    present_commit_authorship(commit.authorship, {}, true);
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
    if (report.commit_id) {
        i18n::println(i18n::Key::FieldCommit, remote_text(*report.commit_id));
    }
    i18n::println(i18n::Key::FieldPath, remote_text(report.path));
    i18n::println(i18n::Key::FieldDestination,
                  remote_text(report.destination_path));
    i18n::println(i18n::Key::FieldLogicalHash,
                  remote_text(report.logical_hash));
    i18n::println(i18n::Key::FieldSize, format_size(report.size));
    return 0;
}

int present_remote_report(const application::RemoteLogReport& report,
                          bool full) {
    const auto colliding = colliding_machine_names(
        report.entries,
        [](const application::RemoteLogEntry& e)
            -> std::pair<std::string_view, std::string_view> {
            if (!e.authorship) {
                return {};
            }
            return {e.authorship->machine_name, e.authorship->machine_id_hex};
        });
    const auto change_label =
        [](application::RemotePathChangeKind kind) -> std::string_view {
        using K = application::RemotePathChangeKind;
        switch (kind) {
            case K::Added:
                return i18n::tr(i18n::Key::RemoteLogChangeAdded);
            case K::Modified:
                return i18n::tr(i18n::Key::RemoteLogChangeModified);
            case K::Deleted:
                return i18n::tr(i18n::Key::RemoteLogChangeDeleted);
            case K::Observed:
                return i18n::tr(i18n::Key::RemoteLogChangeObserved);
        }
        return i18n::tr(i18n::Key::RemoteLogChangeObserved);
    };

    i18n::println(i18n::Key::RemoteLogHeader,
                  remote_text(report.path),
                  report.entries.size(),
                  report.observed_height);
    render_indexed(report.entries, [&](const auto& entry) {
        std::println("  [{}] {} | #{} | {}",
                     change_label(entry.change),
                     remote_text(entry.commit_id),
                     entry.height,
                     platform::clock::format_local_timestamp(entry.created_at));
        if (entry.change != application::RemotePathChangeKind::Deleted) {
            if (entry.type == application::RemoteTreeEntryType::Directory) {
                i18n::println(i18n::Key::RemoteStatDirectory);
            } else {
                std::println("  {}", format_size(entry.size));
                if (full && !entry.logical_hash.empty()) {
                    i18n::println(i18n::Key::FieldLogicalHash,
                                  remote_text(entry.logical_hash));
                }
            }
        }
        present_commit_authorship(entry.authorship, colliding, full);
    });
    return 0;
}

int present_remote_report(const application::RemoteRestoreReport& report) {
    if (report.dry_run) {
        i18n::println(i18n::Key::RemoteRestoreDryRunHeader,
                      remote_text(report.source_prefix));
    } else {
        i18n::println(i18n::Key::RemoteRestoreHeader,
                      remote_text(report.source_prefix));
    }
    if (report.commit_id) {
        i18n::println(i18n::Key::FieldCommit, remote_text(*report.commit_id));
    }
    i18n::println(i18n::Key::FieldHeight, report.observed_height);
    i18n::println(i18n::Key::RemoteRestoreSource,
                  remote_text(report.source_prefix));
    i18n::println(i18n::Key::FieldDestination,
                  remote_text(report.destination_path));
    i18n::println(i18n::Key::FieldFiles, report.file_count);
    i18n::println(i18n::Key::FieldDirectories, report.directory_count);
    i18n::println(i18n::Key::FieldSize, format_size(report.total_bytes));
    return 0;
}

void present_epoch_info(const application::RemoteEpochInfo& epoch) {
    i18n::println(i18n::Key::FieldSequence, epoch.sequence);
    i18n::println(i18n::Key::FieldEpochId, remote_text(epoch.epoch_id));
    i18n::println(i18n::Key::FieldVaultId, remote_text(epoch.vault_id));
    i18n::println(i18n::Key::FieldIssuedAt,
                  platform::clock::format_local_timestamp(epoch.issued_at));
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
    static constexpr std::array<std::pair<C, i18n::Key>, 8> kTable{{
        {C::Content, i18n::Key::ObjectCategoryContent},
        {C::CommitVariant, i18n::Key::ObjectCategoryCommitVariant},
        {C::HeadMarker, i18n::Key::ObjectCategoryHeadMarker},
        {C::Epoch, i18n::Key::ObjectCategoryEpoch},
        {C::Writer, i18n::Key::ObjectCategoryWriter},
        {C::Barrier, i18n::Key::ObjectCategoryBarrier},
        {C::Protocol, i18n::Key::ObjectCategoryProtocol},
        {C::Activity, i18n::Key::ObjectCategoryActivity},
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
    const auto print_marker_metadata =
        [](const std::optional<std::string>& machine_name,
           const std::optional<std::uint64_t>& pid,
           const std::optional<std::int64_t>& started_at_unix) {
            if (machine_name.has_value()) {
                i18n::println(i18n::Key::FieldMachine,
                              remote_text(*machine_name));
            }
            if (pid.has_value()) {
                i18n::println(i18n::Key::FieldPid, *pid);
            }
            if (started_at_unix.has_value()) {
                i18n::println(
                    i18n::Key::FieldStartedAt,
                    platform::clock::format_local_timestamp(*started_at_unix));
            }
        };
    i18n::println(i18n::Key::RemoteWritersHeader, report.writers.size());
    i18n::println(i18n::Key::FieldBarrier,
                  report.barrier_present ? i18n::tr(i18n::Key::FieldPresent)
                                         : i18n::tr(i18n::Key::FieldAbsent));
    if (report.barriers.empty() && report.barrier_identifier.has_value()) {
        i18n::println(i18n::Key::FieldIdentifier,
                      remote_text(*report.barrier_identifier));
    } else if (report.barriers.size() == 1) {
        const auto& barrier = report.barriers.front();
        i18n::println(i18n::Key::FieldIdentifier,
                      remote_text(barrier.identifier));
        print_marker_metadata(
            barrier.machine_name, barrier.pid, barrier.started_at_unix);
    } else if (report.barriers.size() > 1) {
        i18n::println(i18n::Key::FieldBarriers, report.barriers.size());
        render_indexed(report.barriers, [&](const auto& barrier) {
            i18n::println(i18n::Key::FieldIdentifier,
                          remote_text(barrier.identifier));
            print_marker_metadata(
                barrier.machine_name, barrier.pid, barrier.started_at_unix);
        });
    }
    i18n::println(i18n::Key::FieldMaintenanceBlocked,
                  yes_no(report.maintenance_blocked));
    i18n::println(i18n::Key::FieldProtocolConsistent,
                  yes_no(report.protocol_consistent));
    render_indexed(report.writers, [&](const auto& writer) {
        i18n::println(i18n::Key::FieldIdentifier,
                      remote_text(writer.identifier));
        i18n::println(i18n::Key::FieldState,
                      writer.state == application::RemoteWriterState::Invalid
                          ? i18n::tr(i18n::Key::WriterStateInvalid)
                          : i18n::tr(i18n::Key::WriterStateIndeterminate));
        print_marker_metadata(
            writer.machine_name, writer.pid, writer.started_at_unix);
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
                                    Op::RemoteHealth,
                                    Op::RemoteLog,
                                    Op::RemoteRestore};
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
    if (summary.copied > 0) {
        parts.push_back(std::format("cp {}", summary.copied));
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
        progress.listed_objects &&
        state.last_listed_objects != progress.listed_objects) {
        i18n::println(i18n::Key::GcListedObjects, *progress.listed_objects);
        state.last_listed_objects = progress.listed_objects;
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
            if (progress.candidate_content_objects ||
                progress.candidate_commit_variants ||
                progress.candidate_expired_commits ||
                progress.candidate_activities || progress.candidate_bytes) {
                i18n::println(
                    i18n::Key::GcPlanDetails,
                    progress.candidate_content_objects.value_or(0),
                    progress.candidate_commit_variants.value_or(0),
                    progress.candidate_expired_commits.value_or(0),
                    progress.candidate_activities.value_or(0),
                    format_size(progress.candidate_bytes.value_or(0)));
            }
        }
        if (progress.deferred_recent_objects &&
            *progress.deferred_recent_objects > 0) {
            const auto hours = progress.min_age_hours.value_or(0);
            if (*progress.deferred_recent_objects == 1) {
                i18n::println(i18n::Key::GcDeferredRecentSingular, hours);
            } else {
                i18n::println(i18n::Key::GcDeferredRecentPlural,
                              hours,
                              *progress.deferred_recent_objects);
            }
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
        K::ProgressCheckingControls,
        K::ProgressEstablishingBarrier,
        K::ProgressProbingConsistency,
        K::ProgressAnalyzingReachability,
        K::ProgressLoadingActivities,
        K::ProgressReleasingBarrier,
    };
    static_assert(labels.size() ==
                  static_cast<std::size_t>(A::ReleasingBarrier) + 1);
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

void clear_progress_line(ProgressDisplay& display) noexcept {
    if (display.rendered_width == 0) {
        return;
    }
    if (display.terminal.ansi) {
        std::fputs("\r\x1b[2K", stdout);
        if (display.rendered_detail) {
            std::fputs("\x1b[1A\r\x1b[2K", stdout);
        }
    } else {
        std::fputc('\r', stdout);
        const auto columns = platform::terminal_width(display.terminal);
        const auto width =
            std::min(display.rendered_width, columns > 0 ? columns - 1 : 0);
        for (std::size_t i = 0; i < width; ++i) {
            std::fputc(' ', stdout);
        }
        std::fputc('\r', stdout);
    }
    display.rendered_width = 0;
    display.rendered_detail = false;
}

void render_progress_line(ProgressDisplay& display,
                          std::string_view line,
                          std::string_view detail = {}) {
    const auto width = platform::terminal_width(display.terminal) - 1U;
    clear_progress_line(display);
    if (!detail.empty() && display.terminal.ansi && width > 0) {
        std::print("{}\n{}",
                   platform::fit_terminal_text(line, width),
                   platform::fit_terminal_text(detail, width));
        display.rendered_detail = true;
    } else if (!detail.empty()) {
        const auto combined = std::format("{} | {}", line, detail);
        std::print("{}", platform::fit_terminal_text(combined, width));
    } else {
        std::print("{}", platform::fit_terminal_text(line, width));
    }
    display.rendered_width = width;
    display.rendered_last = true;
    std::fflush(stdout);
}

std::string applying_progress_line(const ProgressDisplay& display) {
    const auto applied = display.apply_progress->applied_items.value_or(0);
    const auto total = display.apply_progress->total_items;
    return (display.terminal.interactive
                ? std::string{"      "}
                : std::string{i18n::tr(i18n::Key::SyncStageApplying)} + " | ") +
           i18n::format(i18n::Key::SyncApplyingProgress,
                        applied,
                        total,
                        progress_percent(applied, total));
}

void render_progress_event(ProgressDisplay& display,
                           const application::ActivityProgress& event,
                           std::string_view extra,
                           bool force_complete = false) {
    using A = application::Activity;
    using K = i18n::Key;
    const bool show_plan = display.apply_progress && !force_complete;
    const bool show_file = show_plan && !event.item_path.empty();
    const auto label = progress_label(event, show_plan);
    std::string line = display.indented && (!show_plan || display.terminal.ansi)
                           ? "      "
                           : "";
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
               (!show_plan || (!show_file && (display.full || !total_bytes)))) {
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
    if (display.full && event.bytes_reused != 0) {
        add(i18n::format(K::ProgressReused, format_size(event.bytes_reused)));
    }
    const auto now = std::chrono::steady_clock::now();
    double display_rate = show_file && event.item_bytes ? 0.0 : display.rate;
    if (force_complete && is_byte_transfer(event.activity) && event.bytes > 0) {
        const auto& state = event.activity == A::Uploading
                                ? display.upload_state
                                : display.download_state;
        const auto elapsed =
            std::chrono::duration<double>(now - state.started).count();
        if (elapsed > 0.0) {
            display_rate = static_cast<double>(event.bytes) / elapsed;
        }
    }
    bool has_eta = false;
    if (display_rate > 0 && display_rate < 1e18 &&
        (force_complete ||
         now - display.started >= std::chrono::milliseconds(500))) {
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
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                 now - display.started)
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
        render_progress_line(display, applying_progress_line(display), line);
    } else {
        render_progress_line(display, line);
    }
}

void flush_progress_transfer(ProgressDisplay& display,
                             TransferMetricsState& state) noexcept try {
    if (!display.terminal.interactive || !state.active ||
        state.completed_reported || !state.last_event ||
        (state.last_event->bytes == 0 && state.last_event->objects == 0)) {
        state = {};
        return;
    }
    render_progress_event(display, *state.last_event, state.last_extra, true);
    if (display.rendered_width != 0) {
        std::fputc('\n', stdout);
        display.rendered_width = 0;
        display.rendered_detail = false;
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
                         display.indented ? "      " : "",
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
    clear_progress_line(display);
}

} // namespace

ProgressDisplay::~ProgressDisplay() {
    finish_progress_display(*this);
}

void heartbeat_progress_display(ProgressDisplay& display) noexcept try {
    const auto now = std::chrono::steady_clock::now();
    if (display.terminal.interactive && display.last_event &&
        now - display.last_render >= std::chrono::seconds(1)) {
        render_progress_event(display, *display.last_event, display.last_extra);
    }
} catch (...) {
}

void finish_progress_display(ProgressDisplay& display, bool keep) noexcept try {
    if (!keep) {
        display.upload_state = {};
        display.download_state = {};
        display.last_event.reset();
        display.last_extra.clear();
        display.rendered_last = true;
    } else if (display.terminal.interactive) {
        if (display.in_applying && !display.full) {
            const bool had_upload = display.upload_state.active &&
                                    !display.upload_state.completed_reported &&
                                    (display.upload_state.last_bytes > 0 ||
                                     display.upload_state.last_objects > 0);
            const bool had_download =
                display.download_state.active &&
                !display.download_state.completed_reported &&
                (display.download_state.last_bytes > 0 ||
                 display.download_state.last_objects > 0);
            if (had_upload) {
                flush_progress_transfer(display, display.upload_state);
            }
            if (had_download) {
                flush_progress_transfer(display, display.download_state);
            }
            if (had_upload || had_download) {
                display.activity.reset();
                display.stage_id = 0;
                display.last_event.reset();
                display.last_extra.clear();
                display.rendered_last = true;
                return;
            }
            keep = false;
        } else if (display.last_event &&
                   is_byte_transfer(display.last_event->activity)) {
            auto& state =
                display.last_event->activity == application::Activity::Uploading
                    ? display.upload_state
                    : display.download_state;
            if (state.active && !state.completed_reported && state.last_event &&
                state.last_event->bytes > 0) {
                flush_progress_transfer(display, state);
                display.activity.reset();
                display.stage_id = 0;
                display.last_event.reset();
                display.last_extra.clear();
                display.rendered_last = true;
                return;
            }
        } else if (!display.rendered_last && display.last_event) {
            render_progress_event(
                display, *display.last_event, display.last_extra, true);
        }
    }
    if (display.rendered_width != 0) {
        if (keep) {
            std::fputc('\n', stdout);
            display.rendered_width = 0;
            display.rendered_detail = false;
        } else {
            clear_progress_line(display);
        }
    }
    display.last_event.reset();
    display.last_extra.clear();
    display.rendered_last = true;
    std::fflush(stdout);
} catch (...) {
    display.upload_state = {};
    display.download_state = {};
    display.last_event.reset();
    display.last_extra.clear();
    display.rendered_last = true;
    clear_progress_line(display);
}

void show_progress_display(ProgressDisplay& display,
                           const application::ActivityProgress& raw_event,
                           std::string_view extra) {
    using A = application::Activity;
    using K = i18n::Key;

    if (!display.terminal.interactive) {
        const bool activity_changed = display.activity != raw_event.activity;
        const bool transition =
            activity_changed || display.stage_id != raw_event.stage_id;
        if (transition) {
            display.plain_milestone.reset();
        }
        display.activity = raw_event.activity;
        display.stage_id = raw_event.stage_id;
        if (display.apply_progress && !display.full) {
            return;
        }
        const auto label = progress_label(raw_event);
        if (raw_event.total_objects && *raw_event.total_objects > 0 &&
            raw_event.activity != A::Scanning &&
            raw_event.activity != A::Reobserving) {
            const auto total = *raw_event.total_objects;
            const auto done = std::min(raw_event.objects, total);
            const auto percent = progress_percent(done, total);
            if (display.plain_milestone != percent / 10) {
                display.plain_milestone = percent / 10;
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
        auto& state = raw_event.activity == A::Uploading
                          ? display.upload_state
                          : display.download_state;
        if (display.in_applying && !display.full) {
            auto& other = raw_event.activity == A::Uploading
                              ? display.download_state
                              : display.upload_state;
            if (other.active && !other.completed_reported &&
                (other.last_bytes > 0 || other.last_objects > 0)) {
                flush_progress_transfer(display, other);
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
                if (display.apply_progress) {
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
    } else if (!display.in_applying && display.download_state.active &&
               !display.download_state.completed_reported &&
               display.download_state.last_bytes > 0) {
        flush_progress_transfer(display, display.download_state);
    }

    // Only the retained summary uses totals accumulated across transfer
    // batches.
    if (display.apply_progress) {
        event = raw_event;
    }
    const bool transition = display.activity != event.activity ||
                            display.stage_id != event.stage_id;
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
        if (display.full && display.activity) {
            finish_progress_display(display, true);
        } else {
            clear_progress_line(display);
        }
        display.activity = event.activity;
        display.stage_id = event.stage_id;
        display.started = now;
        display.last_render = now;
        display.last_value = value;
        display.last_objects = event.objects;
        display.rate =
            is_byte_transfer(event.activity)
                ? (event.activity == A::Uploading ? display.upload_state.rate
                                                  : display.download_state.rate)
                : 0.0;
        display.was_complete = false;
        display.last_event = event;
        display.last_extra = std::string{extra};
        display.rendered_last = false;
        render_progress_event(display, event, extra);
        return;
    }

    const auto dt =
        std::chrono::duration<double>(now - display.last_render).count();
    if (is_byte_transfer(event.activity)) {
        display.rate = event.activity == A::Uploading
                           ? display.upload_state.rate
                           : display.download_state.rate;
    } else if (dt > 0 && value >= display.last_value) {
        const auto instantaneous =
            static_cast<double>(value - display.last_value) / dt;
        display.rate = display.rate <= 0.0
                           ? instantaneous
                           : display.rate + (instantaneous - display.rate) *
                                                (1.0 - std::exp(-dt / 2.5));
    }

    const bool objects_advanced = event.objects != display.last_objects;
    display.last_event = event;
    display.last_extra = std::string{extra};
    display.rendered_last = false;

    if (now - display.last_render < std::chrono::milliseconds(200) &&
        !(complete && (!display.was_complete || objects_advanced))) {
        return;
    }

    render_progress_event(display, event, extra);
    display.last_render = now;
    display.last_value = value;
    display.last_objects = event.objects;
    display.was_complete = complete;
}

void update_progress_display(ProgressDisplay& display,
                             const application::ExecutionProgress& progress,
                             application::Operation operation) {
    std::visit(
        [&](const auto& event) {
            using T = std::decay_t<decltype(event)>;
            using A = application::Activity;
            if constexpr (std::is_same_v<T, application::ActivityProgress>) {
                show_progress_display(display, event);
            } else if constexpr (std::is_same_v<T, application::SyncProgress>) {
                if (event.stage == application::SyncStage::Applying &&
                    event.applied_items && display.apply_progress &&
                    event.total_items == display.apply_progress->total_items) {
                    const auto previous = progress_percent(
                        display.apply_progress->applied_items.value_or(0),
                        event.total_items);
                    display.apply_progress->applied_items = event.applied_items;
                    if (display.terminal.interactive) {
                        if (display.last_event) {
                            render_progress_event(display,
                                                  *display.last_event,
                                                  display.last_extra);
                        } else {
                            render_progress_line(
                                display, applying_progress_line(display));
                        }
                    } else if (previous / 10 !=
                               progress_percent(*event.applied_items,
                                                event.total_items) /
                                   10) {
                        std::println("{}", applying_progress_line(display));
                    }
                    return;
                }
                const bool was_applying = display.in_applying;
                const bool keep_stage =
                    display.full ||
                    (was_applying &&
                     event.stage != application::SyncStage::Applying);
                if (display.apply_progress) {
                    clear_progress_line(display);
                }
                if (display.terminal.interactive && display.apply_progress &&
                    display.apply_progress->applied_items ==
                        display.apply_progress->total_items) {
                    std::println("{}", applying_progress_line(display));
                }
                finish_progress_display(display, keep_stage);
                display.started = std::chrono::steady_clock::now();
                display.apply_progress.reset();
                if (was_applying &&
                    event.stage != application::SyncStage::Applying) {
                    display.upload_state = {};
                    display.download_state = {};
                }
                display.in_applying =
                    event.stage == application::SyncStage::Applying;
                display.indented = true;
                display.activity.reset();
                display.stage_id = 0;
                if (display.in_applying && event.total_items > 0) {
                    display.apply_progress = event;
                    if (display.terminal.interactive) {
                        present(event, operation);
                        render_progress_line(display,
                                             applying_progress_line(display));
                    } else {
                        std::println("{}", applying_progress_line(display));
                    }
                } else {
                    present(event, operation);
                }
            } else if constexpr (std::is_same_v<T, application::FsckProgress>) {
                if (display.fsck.last_stage != event.stage) {
                    const bool keep_fsck =
                        display.fsck.last_stage ==
                            application::FsckStage::AuditingContent ||
                        display.full;
                    finish_progress_display(display, keep_fsck);
                    display.started = std::chrono::steady_clock::now();
                    display.indented = true;
                    display.activity.reset();
                    display.stage_id = 0;
                    if (display.terminal.interactive) {
                        auto stage = event;
                        stage.total_objects.reset();
                        present(stage, display.fsck);
                    }
                }
                if (!display.terminal.interactive || event.total_objects == 0) {
                    present(event, display.fsck);
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
                    show_progress_display(
                        display,
                        {.activity = A::Auditing,
                         .bytes = event.wire_download_bytes,
                         .total_bytes = event.total_wire_bytes,
                         .objects = event.completed_objects,
                         .total_objects = *event.total_objects},
                        detail);
                }
            } else {
                const auto gc_sub_activity =
                    [](application::GarbageCollectSubStage sub)
                    -> std::optional<A> {
                    using S = application::GarbageCollectSubStage;
                    switch (sub) {
                        case S::None:
                            return std::nullopt;
                        case S::CheckingControls:
                            return A::CheckingControls;
                        case S::EstablishingBarrier:
                            return A::EstablishingBarrier;
                        case S::ProbingConsistency:
                            return A::ProbingConsistency;
                        case S::ListingRemote:
                            return A::Listing;
                        case S::AuthenticatingHistory:
                            return A::Authenticating;
                        case S::AnalyzingReachability:
                            return A::AnalyzingReachability;
                        case S::LoadingActivities:
                            return A::LoadingActivities;
                        case S::RemovingObjects:
                            return A::Removing;
                        case S::ReleasingBarrier:
                            return A::ReleasingBarrier;
                    }
                    return std::nullopt;
                };
                if (display.gc.last_stage != event.stage) {
                    const bool keep =
                        display.gc.last_stage ==
                            application::GarbageCollectStage::Applying ||
                        (display.full && display.gc.last_stage.has_value());
                    finish_progress_display(display, keep);
                    display.started = std::chrono::steady_clock::now();
                    display.indented = true;
                    display.activity.reset();
                    display.stage_id = 0;
                }
                present(event, display.gc);
                if (const auto activity = gc_sub_activity(event.sub_stage)) {
                    application::ActivityProgress ap{.activity = *activity};
                    if (*activity == A::Authenticating && event.commits_total &&
                        *event.commits_total > 0) {
                        ap.objects = event.commits_processed.value_or(0);
                        ap.total_objects = *event.commits_total;
                        show_progress_display(display, ap);
                    } else if (*activity == A::Removing &&
                               event.candidate_count &&
                               *event.candidate_count > 0) {
                        ap.objects = event.removed_objects;
                        ap.total_objects = *event.candidate_count;
                        if (event.candidate_bytes &&
                            *event.candidate_bytes > 0) {
                            ap.bytes = event.removed_bytes;
                            ap.total_bytes = *event.candidate_bytes;
                        }
                        show_progress_display(display, ap);
                    } else if (display.terminal.interactive) {
                        show_progress_display(display, ap);
                    }
                }
            }
        },
        progress);
    std::fflush(stdout);
}

std::string format_machine_label(std::string_view name,
                                 std::string_view id_hex,
                                 bool show_id,
                                 bool full_id) {
    const auto clean_name = sanitize_terminal_text(name);
    const auto display_id =
        (full_id || id_hex.size() <= 4) ? id_hex : id_hex.substr(0, 4);
    if (clean_name.empty()) {
        if (display_id.empty()) {
            return std::string{i18n::tr(i18n::Key::LabelUnknown)};
        }
        return std::format("[{}]", sanitize_terminal_text(display_id));
    }
    if (show_id && !display_id.empty()) {
        return std::format(
            "{} [{}]", clean_name, sanitize_terminal_text(display_id));
    }
    return clean_name;
}

std::string_view commit_origin_label(std::uint8_t origin_op) {
    using O = application::RemoteCommitOrigin;
    switch (static_cast<O>(origin_op)) {
        case O::Sync:
            return "sync";
        case O::Repack:
            return "repack";
        case O::ResolveMissing:
            return "resolve-missing";
        case O::Unknown:
        default:
            return i18n::tr(i18n::Key::LabelUnknown);
    }
}

std::string_view activity_operation_label(std::uint8_t op) {
    using O = application::RemoteActivityOperation;
    switch (static_cast<O>(op)) {
        case O::Fsck:
            return "fsck";
        case O::GarbageCollect:
            return "gc";
        case O::RemoveWriter:
            return "gc remove-writer";
        case O::RemoveBarrier:
            return "gc remove-barrier";
        default:
            return i18n::tr(i18n::Key::LabelUnknown);
    }
}

std::string_view activity_outcome_label(std::uint8_t outcome) {
    using R = application::RemoteActivityOutcome;
    static constexpr std::array<std::pair<R, i18n::Key>, 6> kTable{{
        {R::Succeeded, i18n::Key::LabelStatusOk},
        {R::IssuesFound, i18n::Key::LabelStatusIssuesFound},
        {R::Blocked, i18n::Key::LabelStatusBlocked},
        {R::Cancelled, i18n::Key::LabelStatusCancelled},
        {R::Failed, i18n::Key::LabelStatusFailed},
        {R::Uncertain, i18n::Key::LabelStatusUncertain},
    }};
    return enum_tr(static_cast<R>(outcome), kTable, i18n::Key::LabelUnknown);
}

std::string format_activity_metrics(std::uint8_t op,
                                    std::uint64_t primary,
                                    std::uint64_t secondary,
                                    std::uint64_t bytes,
                                    std::uint32_t flags) {
    using O = application::RemoteActivityOperation;
    switch (static_cast<O>(op)) {
        case O::Fsck:
            if (primary > 0 || bytes > 0) {
                return i18n::format(
                    i18n::Key::LabelMetricFsck, primary, format_size(bytes));
            }
            return {};
        case O::GarbageCollect:
            if ((flags & application::remote_activity_flag_analysis_only) !=
                0U) {
                return i18n::format(i18n::Key::LabelMetricGcCandidates,
                                    primary > 0 ? primary : secondary);
            }
            if (primary > 0 || secondary > 0) {
                return i18n::format(
                    i18n::Key::LabelMetricGcRemoved, secondary, primary);
            }
            return {};
        case O::RemoveWriter:
        case O::RemoveBarrier:
        default:
            return {};
    }
}

std::string format_activity_flags(std::uint32_t flags) {
    std::string out;
    const auto append = [&](i18n::Key key) {
        if (!out.empty()) {
            out += ", ";
        }
        out += i18n::tr(key);
    };
    if ((flags & application::remote_activity_flag_analysis_only) != 0U) {
        append(i18n::Key::LabelFlagAnalysisOnly);
    }
    if ((flags & application::remote_activity_flag_barrier_already_absent) !=
        0U) {
        append(i18n::Key::LabelFlagAlreadyAbsent);
    }
    if ((flags & application::remote_activity_flag_barrier_release_failed) !=
        0U) {
        append(i18n::Key::LabelFlagBarrierReleaseFailed);
    }
    if ((flags & application::remote_activity_flag_mutation_uncertain) != 0U) {
        append(i18n::Key::LabelFlagMutationUncertain);
    }
    return out;
}

int present_remote_dispatch(const application::RemoteSummaryReport& report,
                            bool full) {
    return present_remote_report(report, full);
}

int present_remote_dispatch(const application::RemoteLogReport& report,
                            bool full) {
    return present_remote_report(report, full);
}

template <typename Report>
int present_remote_dispatch(const Report& report, bool) {
    return present_remote_report(report);
}

int response_exit_code(const application::Response& response) noexcept {
    if (const auto* sync =
            std::get_if<application::SyncCompleted>(&response.data)) {
        int code = sync->partial ? 2 : 0;
        if (response.inventory_audit &&
            (response.inventory_audit->missing_content != 0 ||
             response.inventory_audit->orphan_content != 0 ||
             response.inventory_audit->unknown_objects != 0)) {
            code = 2;
        }
        return code;
    }
    if (const auto* plan =
            std::get_if<application::PlanReport>(&response.data)) {
        return plan->pending_paths.empty() ? 0 : 2;
    }
    return 0;
}

int present(const application::Response& response, bool full, bool quiet) {
    if (quiet && response_exit_code(response) == 0) {
        if (response.activity_publish_warning &&
            !response.activity_publish_warning->empty()) {
            std::println(stderr,
                         "{} {}",
                         i18n::tr(i18n::Key::LabelWarning),
                         i18n::format(i18n::Key::LabelActivityPublishWarning,
                                      sanitize_terminal_text(
                                          *response.activity_publish_warning)));
        }
        return 0;
    }
    const auto op = response.operation;
    const int result_code = std::visit(
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
                if (data.repaired > 0) {
                    i18n::println(data.repaired == 1
                                      ? i18n::Key::SyncRepairedSingular
                                      : i18n::Key::SyncRepairedPlural,
                                  data.repaired);
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
                if (data.remaining_barriers_count > 0) {
                    std::println(
                        "{} {}",
                        i18n::tr(i18n::Key::LabelWarning),
                        i18n::format(
                            i18n::Key::ManualBarrierRemovalBarriersRemain,
                            data.remaining_barriers_count));
                }
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
                const auto print_deferred_recent = [&](std::uint32_t hours,
                                                       std::size_t count) {
                    if (count == 0) {
                        return;
                    }
                    if (count == 1) {
                        i18n::println(i18n::Key::GcDeferredRecentSingular,
                                      hours);
                    } else {
                        i18n::println(
                            i18n::Key::GcDeferredRecentPlural, hours, count);
                    }
                };
                if (data.dry_run) {
                    if (data.candidate_objects == 0) {
                        print_ok_line(i18n::tr(i18n::Key::GcCandidatesNone));
                    } else {
                        i18n::println(i18n::Key::GcDryRunSummary,
                                      data.candidate_objects,
                                      data.candidate_content_objects,
                                      data.candidate_commit_variants,
                                      data.candidate_activities);
                        if (data.candidate_expired_commits > 0 ||
                            data.candidate_bytes > 0 || full) {
                            i18n::println(i18n::Key::GcPlanDetails,
                                          data.candidate_content_objects,
                                          data.candidate_commit_variants,
                                          data.candidate_expired_commits,
                                          data.candidate_activities,
                                          format_size(data.candidate_bytes));
                        }
                    }
                    print_deferred_recent(data.min_age_hours,
                                          data.deferred_recent_objects);
                    i18n::println(i18n::Key::GcDryRunCompleted);
                    return 0;
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
                    print_deferred_recent(data.min_age_hours,
                                          data.deferred_recent_objects);
                    return 0;
                }
                print_ok_line(i18n::tr(i18n::Key::GcCompleted));
                auto metrics =
                    i18n::format(i18n::Key::GcSummary, data.candidate_objects) +
                    " " +
                    i18n::format(i18n::Key::GcConfirmedRemovals,
                                 data.removed_objects);
                if (data.removed_bytes > 0) {
                    metrics +=
                        " | " + i18n::format(i18n::Key::GcReclaimedBytes,
                                             format_size(data.removed_bytes));
                }
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
                if (data.candidate_objects > 0 &&
                    (data.candidate_expired_commits > 0 ||
                     data.candidate_bytes > 0 || full)) {
                    i18n::println(i18n::Key::GcPlanDetails,
                                  data.candidate_content_objects,
                                  data.candidate_commit_variants,
                                  data.candidate_expired_commits,
                                  data.candidate_activities,
                                  format_size(data.candidate_bytes));
                }
                print_deferred_recent(data.min_age_hours,
                                      data.deferred_recent_objects);
                return 0;
            } else if constexpr (std::is_same_v<
                                     T,
                                     application::ResolveMissingCompleted>) {
                if (op != Op::ResolveMissing) {
                    return 1;
                }
                if (data.dry_run) {
                    if (data.resolved_count > 0) {
                        i18n::println(i18n::Key::ResolveMissingDryRunHeader,
                                      data.resolved_count);
                        for (const auto& path : data.resolved_paths) {
                            std::println("  {}", sanitize_terminal_text(path));
                        }
                        i18n::println(i18n::Key::ResolveMissingDryRunCompleted);
                    } else {
                        i18n::println(i18n::Key::ResolveMissingNone);
                    }
                    return 0;
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
            } else if constexpr (std::is_same_v<T,
                                                application::RepackCompleted>) {
                if (op != Op::Repack) {
                    return 1;
                }
                const auto print_inventory = [&] {
                    if (full) {
                        i18n::println(i18n::Key::RepackInventorySummary,
                                      data.existing_packs,
                                      data.healthy_packs_kept,
                                      data.dirty_packs_detected,
                                      data.loose_small_blobs_detected);
                    }
                };
                if (!data.actionable) {
                    print_ok_line(i18n::tr(i18n::Key::RepackNothingToDo));
                    if (data.dirty_packs_detected > 0) {
                        i18n::println(i18n::Key::RepackDirtyHint,
                                      data.dirty_packs_detected);
                    }
                    print_inventory();
                    return 0;
                }
                if (data.dry_run) {
                    i18n::println(i18n::Key::RepackPlanSummary,
                                  data.repacked_blobs,
                                  format_size(data.repacked_plaintext_bytes),
                                  data.new_packs);
                    i18n::println(i18n::Key::RepackSourcesSummary,
                                  data.source_loose_blobs,
                                  data.source_clean_packs,
                                  data.source_dirty_packs);
                    print_inventory();
                    i18n::println(i18n::Key::RepackDryRunCompleted);
                    return 0;
                }
                print_ok_line(i18n::tr(i18n::Key::RepackCompleted));
                i18n::println(i18n::Key::RepackCompletedSummary,
                              data.repacked_blobs,
                              format_size(data.repacked_plaintext_bytes),
                              data.new_packs);
                i18n::println(i18n::Key::RepackSourcesSummary,
                              data.source_loose_blobs,
                              data.source_clean_packs,
                              data.source_dirty_packs);
                if (data.wire_upload_bytes || data.physical_objects_uploaded) {
                    i18n::println(i18n::Key::RepackWireSummary,
                                  format_size(data.wire_upload_bytes),
                                  format_plural(data.physical_objects_uploaded,
                                                i18n::Key::ProgressObject,
                                                i18n::Key::ProgressObjects));
                }
                print_inventory();
                if (full && !data.published_commit_id.empty()) {
                    i18n::println(
                        i18n::Key::RepackPublishedCommit,
                        sanitize_terminal_text(data.published_commit_id),
                        data.published_height);
                }
                if (data.source_clean_packs + data.source_dirty_packs > 0) {
                    i18n::println(i18n::Key::RepackRetentionHint);
                }
                return 0;
            } else {
                return 1;
            }
        },
        response.data);
    if (response.activity_publish_warning &&
        !response.activity_publish_warning->empty()) {
        std::println(stderr,
                     "{} {}",
                     i18n::tr(i18n::Key::LabelWarning),
                     i18n::format(i18n::Key::LabelActivityPublishWarning,
                                  sanitize_terminal_text(
                                      *response.activity_publish_warning)));
    }
    return result_code;
}

int present(const application::InspectionResponse& response, bool full) {
    return std::visit(
        [&](const auto& report) -> int {
            if (inspection_op_matches(response)) {
                return present_remote_dispatch(report, full);
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
    static constexpr std::array<std::pair<C, i18n::Key>, 9> kErrorFormats{{
        {C::PlanFailure, i18n::Key::ErrorPlanCalculation},
        {C::FsckFailure, i18n::Key::ErrorFsckFailed},
        {C::GarbageCollectionFailure, i18n::Key::ErrorGcCancelled},
        {C::RepackFailure, i18n::Key::ErrorRepackFailed},
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

int present(const application::DiagnosticsReport& report,
            std::string_view version,
            bool quiet) {
    if (quiet && report.overall_ok) {
        return 0;
    }
    if (!quiet) {
        i18n::println(i18n::Key::DiagnosticsHeader);
        i18n::println(i18n::Key::DiagnosticsVersion, version);
        i18n::println(i18n::Key::DiagnosticsOs,
                      sanitize_terminal_text(report.os_name));
        i18n::println(i18n::Key::DiagnosticsAppData,
                      sanitize_terminal_text(
                          platform::path::to_utf8(report.app_data_dir)));
        if (report.app_data_free_bytes) {
            i18n::println(i18n::Key::DiagnosticsFreeSpace,
                          format_size(*report.app_data_free_bytes));
        }
        i18n::println(report.config_exists
                          ? i18n::Key::DiagnosticsConfigFound
                          : i18n::Key::DiagnosticsConfigMissing,
                      sanitize_terminal_text(
                          platform::path::to_utf8(report.config_path)));

        i18n::println(i18n::Key::DiagnosticsRcloneHeader);
        if (report.rclone.found) {
            i18n::println(
                i18n::Key::DiagnosticsRcloneFound,
                sanitize_terminal_text(
                    platform::path::to_utf8(report.rclone.executable)),
                report.rclone.version.empty()
                    ? std::string{i18n::tr(i18n::Key::LabelUnknown)}
                    : sanitize_terminal_text(report.rclone.version),
                sanitize_terminal_text(report.rclone.minimum_version));
            if (!report.rclone.meets_minimum &&
                !report.rclone.version.empty()) {
                i18n::println(
                    i18n::Key::DiagnosticsRcloneOutdated,
                    sanitize_terminal_text(report.rclone.version),
                    sanitize_terminal_text(report.rclone.minimum_version));
            }
        } else {
            i18n::println(i18n::Key::DiagnosticsRcloneMissing,
                          sanitize_terminal_text(report.rclone.detail));
        }

        i18n::println(i18n::Key::DiagnosticsDaemonHeader);
        const std::string autostart_summary =
            !report.daemon.autostart_supported
                ? std::string{"unsupported"}
                : (report.daemon.autostart_installed
                       ? std::format("{} ({})",
                                     i18n::tr(i18n::Key::LabelYes),
                                     sanitize_terminal_text(
                                         report.daemon.autostart_method))
                       : std::string{i18n::tr(i18n::Key::LabelNo)});
        if (report.daemon.running) {
            i18n::println(i18n::Key::DiagnosticsDaemonRunning,
                          report.daemon.pid,
                          report.daemon.ipc_port,
                          report.daemon.secure_pages_locked
                              ? i18n::tr(i18n::Key::LabelYes)
                              : i18n::tr(i18n::Key::LabelNo),
                          autostart_summary);
        } else {
            i18n::println(i18n::Key::DiagnosticsDaemonStopped,
                          autostart_summary);
        }
        if (!report.daemon.control_metadata_valid ||
            !report.daemon.detail.empty()) {
            i18n::println(i18n::Key::DiagnosticsDaemonInvalid,
                          sanitize_terminal_text(report.daemon.detail));
        }

        if (report.profiles.empty()) {
            i18n::println(i18n::Key::DiagnosticsProfilesNone);
        } else {
            for (const auto& entry : report.profiles) {
                i18n::println(i18n::Key::DiagnosticsProfileHeader,
                              sanitize_terminal_text(entry.profile.name),
                              entry.healthy
                                  ? i18n::tr(i18n::Key::LabelOk)
                                  : i18n::tr(i18n::Key::LabelWarning));
                std::string state_label{
                    application::to_string(entry.local_state)};
                if (entry.local_state ==
                    application::ProfileLocalState::Running) {
                    if (const auto active_op =
                            application::active_profile_operation(
                                entry.activity)) {
                        state_label = std::format("Running ({})", *active_op);
                    }
                }
                std::println("  {} -> {} ({})",
                             sanitize_terminal_text(platform::path::to_utf8(
                                 entry.profile.local_dir)),
                             sanitize_terminal_text(entry.profile.remote_dir),
                             state_label);
                if (entry.local_free_bytes) {
                    i18n::println(i18n::Key::DiagnosticsFreeSpace,
                                  format_size(*entry.local_free_bytes));
                }
                if (entry.daemon_state.has_value()) {
                    std::string daemon_detail = std::format(
                        "watch={}",
                        entry.daemon_watcher_active ? "active" : "inactive");
                    if (!entry.daemon_active_stage.empty()) {
                        daemon_detail += std::format(
                            ", stage={}",
                            sanitize_terminal_text(entry.daemon_active_stage));
                    }
                    if (!entry.daemon_error.empty()) {
                        daemon_detail += std::format(
                            ", error={}",
                            sanitize_terminal_text(entry.daemon_error));
                    }
                    i18n::println(i18n::Key::DiagnosticsProfileDaemon,
                                  sanitize_terminal_text(*entry.daemon_state),
                                  daemon_detail);
                }
                if (entry.ignore_file_present) {
                    if (entry.ignore_file_valid) {
                        i18n::println(i18n::Key::DiagnosticsIgnorePresent);
                    } else {
                        i18n::println(
                            i18n::Key::DiagnosticsIgnoreInvalid,
                            entry.ignore_error_line.value_or(0U),
                            sanitize_terminal_text(entry.ignore_error_detail));
                    }
                }
                if (!entry.healthy && !entry.detail.empty()) {
                    std::println("  {} {}",
                                 i18n::tr(i18n::Key::LabelWarning),
                                 sanitize_terminal_text(entry.detail));
                }
            }
        }
    }

    if (report.overall_ok) {
        print_ok_line(i18n::tr(i18n::Key::DiagnosticsOverallOk));
    } else {
        print_status_line(style::yellow,
                          i18n::Key::LabelWarning,
                          i18n::tr(i18n::Key::DiagnosticsOverallIssues));
    }
    return 0;
}

int present(const application::LocalConflictsReport& report, bool quiet) {
    if (quiet) {
        return 0;
    }
    i18n::println(i18n::Key::ConflictsHeader,
                  sanitize_terminal_text(report.profile_name),
                  report.total_artifacts);
    if (report.groups.empty()) {
        i18n::println(i18n::Key::ConflictsNone);
        return 0;
    }
    for (const auto& group : report.groups) {
        if (group.canonical_exists) {
            i18n::println(i18n::Key::ConflictsCanonicalPresent,
                          sanitize_terminal_text(group.canonical_path),
                          format_size(group.canonical_size),
                          platform::clock::format_local_timestamp(
                              group.canonical_modified_at));
        } else {
            i18n::println(i18n::Key::ConflictsCanonicalMissing,
                          sanitize_terminal_text(group.canonical_path));
        }
        for (const auto& art : group.artifacts) {
            std::string origin_label;
            if (art.origin == application::ConflictOrigin::Local) {
                origin_label =
                    std::string{i18n::tr(i18n::Key::ConflictsOriginLocal)};
            } else if (art.origin == application::ConflictOrigin::Remote) {
                origin_label =
                    std::string{i18n::tr(i18n::Key::ConflictsOriginRemote)};
            } else {
                origin_label =
                    i18n::format(i18n::Key::ConflictsOriginBranch,
                                 sanitize_terminal_text(art.origin_tag));
            }
            i18n::println(
                i18n::Key::ConflictsArtifactItem,
                sanitize_terminal_text(art.path),
                origin_label,
                format_size(art.size),
                platform::clock::format_local_timestamp(art.modified_at));
        }
    }
    i18n::println(i18n::Key::ConflictsTotalSummary,
                  report.total_artifacts,
                  report.groups.size());
    return 0;
}

int present(const application::ResolveConflictReport& report, bool quiet) {
    if (quiet) {
        return 0;
    }
    if (report.dry_run) {
        const std::string kept =
            report.selected_artifact
                ? sanitize_terminal_text(*report.selected_artifact)
                : "canonical";
        i18n::println(i18n::Key::ConflictsResolveDryRunHeader,
                      sanitize_terminal_text(report.canonical_path),
                      kept);
        for (const auto& art : report.removed_artifacts) {
            i18n::println(i18n::Key::ConflictsResolveRemovedList,
                          sanitize_terminal_text(art));
        }
        return 0;
    }
    if (report.choice == application::ConflictResolutionChoice::KeepCanonical) {
        print_ok_line(
            i18n::format(i18n::Key::ConflictsResolveCompletedKeepCanonical,
                         sanitize_terminal_text(report.canonical_path),
                         report.removed_artifacts.size()));
    } else {
        print_ok_line(i18n::format(
            i18n::Key::ConflictsResolveCompletedKeepArtifact,
            sanitize_terminal_text(report.canonical_path),
            sanitize_terminal_text(report.selected_artifact.value_or("")),
            report.removed_artifacts.size()));
    }
    return 0;
}

int present(const application::IgnoreCheckReport& report, bool quiet) {
    if (quiet) {
        return 0;
    }
    i18n::println(i18n::Key::IgnoreCheckHeader,
                  sanitize_terminal_text(report.profile_name));
    for (const auto& item : report.items) {
        std::string_view disposition;
        switch (item.disposition) {
            case application::IgnoreDispositionKind::Managed:
                disposition = i18n::tr(i18n::Key::IgnoreDispositionManaged);
                break;
            case application::IgnoreDispositionKind::IgnoredProtected:
                disposition = i18n::tr(i18n::Key::IgnoreDispositionProtected);
                break;
            case application::IgnoreDispositionKind::IgnoredDisposable:
                disposition = i18n::tr(i18n::Key::IgnoreDispositionDisposable);
                break;
        }
        std::string source;
        if (item.reserved_internal) {
            source = std::string{i18n::tr(i18n::Key::IgnoreSourceReserved)};
        } else if (item.matched_rule) {
            source = i18n::format(i18n::Key::IgnoreSourceRule,
                                  item.rule_line,
                                  sanitize_terminal_text(item.rule_text));
        } else {
            source = std::string{i18n::tr(i18n::Key::IgnoreSourceDefault)};
        }
        const std::string display_path =
            item.is_directory ? item.logical_path + "/" : item.logical_path;
        std::println("  {} -> {} ({})",
                     sanitize_terminal_text(display_path),
                     disposition,
                     source);
    }
    return 0;
}

int present(const application::IgnoreInitReport& report, bool quiet) {
    if (quiet) {
        return 0;
    }
    const auto preset_name = application::to_string(report.preset);
    if (report.dry_run) {
        i18n::println(i18n::Key::IgnoreInitDryRunHeader, preset_name);
        std::print("{}", report.content);
        if (!report.content.empty() && report.content.back() != '\n') {
            std::println("");
        }
        return 0;
    }
    print_ok_line(i18n::format(report.overwritten
                                   ? i18n::Key::IgnoreInitOverwritten
                                   : i18n::Key::IgnoreInitCreated,
                               sanitize_terminal_text(report.profile_name),
                               preset_name));
    return 0;
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

std::string
format_compact_summary(const application::DaemonStatusReport& report) {
    return std::format("running={}, pid={}, port={}, profiles={}",
                       report.running ? "yes" : "no",
                       report.pid,
                       report.ipc_port,
                       report.profiles.size());
}

std::string
format_compact_summary(const application::DaemonAutostartStatus& status) {
    return std::format("supported={}, installed={}, method={}",
                       status.supported ? "yes" : "no",
                       status.installed ? "yes" : "no",
                       status.method);
}

std::string_view
execution_status_label(application::ProfileExecutionStatus status) {
    using S = application::ProfileExecutionStatus;
    static constexpr std::array<std::pair<S, i18n::Key>, 11> kTable{{
        {S::InProgress, i18n::Key::LabelStatusInProgress},
        {S::Succeeded, i18n::Key::LabelStatusOk},
        {S::SucceededNoChanges, i18n::Key::LabelStatusNoChanges},
        {S::SucceededDownloadedOnly, i18n::Key::LabelStatusDownloadedOnly},
        {S::SucceededPartial, i18n::Key::LabelStatusPartial},
        {S::IssuesFound, i18n::Key::LabelStatusIssuesFound},
        {S::Blocked, i18n::Key::LabelStatusBlocked},
        {S::Cancelled, i18n::Key::LabelStatusCancelled},
        {S::Failed, i18n::Key::LabelStatusFailed},
        {S::Uncertain, i18n::Key::LabelStatusUncertain},
        {S::Interrupted, i18n::Key::LabelStatusInterrupted},
    }};
    for (const auto& [candidate, key] : kTable) {
        if (candidate == status) {
            return i18n::tr(key);
        }
    }
    return i18n::tr(i18n::Key::LabelUnknown);
}

std::string_view
overview_problem_message(application::ProfileLocalProblem problem) {
    static constexpr auto keys = std::to_array<i18n::Key>({
        i18n::Key::WizardProblemUnspecified,
        i18n::Key::WizardProblemName,
        i18n::Key::WizardProblemPaths,
        i18n::Key::WizardProblemDirectory,
        i18n::Key::WizardProblemKey,
        i18n::Key::WizardProblemDatabase,
        i18n::Key::WizardProblemLock,
        i18n::Key::WizardProblemSidecar,
        i18n::Key::WizardProblemJournal,
        i18n::Key::WizardProblemWorkspace,
        i18n::Key::WizardProblemSnapshot,
        i18n::Key::WizardProblemCleanup,
    });
    const auto idx = static_cast<std::size_t>(problem);
    if (idx < keys.size()) {
        return i18n::tr(keys[idx]);
    }
    return i18n::tr(i18n::Key::WizardProblemUnspecified);
}

namespace {

std::string format_sync_interval_label(std::uint32_t seconds) {
    if (seconds == 0U) {
        return std::string{i18n::tr(i18n::Key::LabelDisabled)};
    }
    if (seconds % 60U == 0U) {
        return std::format("{}m", seconds / 60U);
    }
    return std::format("{}s", seconds);
}

std::string format_watch_label(const application::DaemonProfileStatus& p) {
    if (!p.watch_enabled) {
        return std::string{i18n::tr(i18n::Key::LabelNo)};
    }
    if (p.watcher_active) {
        return "active";
    }
    return p.watcher_degraded ? "degraded" : "inactive";
}

std::string format_active_stage_progress(
    const application::DaemonProfileStatus& p,
    bool include_bytes) {
    if (p.active_stage.empty()) {
        return std::string{i18n::tr(i18n::Key::OverviewDetailSyncing)};
    }
    std::string detail;
    if (p.active_total_objects.has_value()) {
        detail = std::format("{}/{} objects",
                             p.active_objects,
                             *p.active_total_objects);
    } else if (p.active_objects > 0) {
        detail = std::format("{} objects", p.active_objects);
    }
    if (include_bytes) {
        if (p.active_total_bytes.has_value()) {
            if (!detail.empty()) {
                detail += ", ";
            }
            detail += std::format("{}/{}",
                                  format_size(p.active_bytes),
                                  format_size(*p.active_total_bytes));
        } else if (p.active_bytes > 0) {
            if (!detail.empty()) {
                detail += ", ";
            }
            detail += format_size(p.active_bytes);
        }
    }
    if (detail.empty()) {
        return std::format("{}...", sanitize_terminal_text(p.active_stage));
    }
    return std::format(
        "{} ({})", sanitize_terminal_text(p.active_stage), detail);
}

std::string format_overview_last_sync(const OverviewProfileRow& row) {
    const application::ProfileExecutionSummary* chosen = nullptr;
    if (row.activity.last_attempt &&
        row.activity.last_attempt->operation ==
            application::ProfileOperationKind::Sync &&
        (!row.activity.last_complete_sync ||
         row.activity.last_attempt->started_at >
             row.activity.last_complete_sync->started_at)) {
        chosen = &*row.activity.last_attempt;
    } else if (row.activity.last_complete_sync) {
        chosen = &*row.activity.last_complete_sync;
    }

    std::optional<std::int64_t> sync_ts;
    std::string status_text;
    if (chosen != nullptr) {
        sync_ts = chosen->finished_at.value_or(chosen->started_at);
        status_text = std::string{execution_status_label(chosen->status)};
    }
    if (row.daemon_profile && row.daemon_profile->last_sync_finished_at &&
        (!sync_ts || *row.daemon_profile->last_sync_finished_at > *sync_ts)) {
        sync_ts = *row.daemon_profile->last_sync_finished_at;
        if (!row.daemon_profile->last_outcome.empty()) {
            status_text =
                sanitize_terminal_text(row.daemon_profile->last_outcome);
        } else if (status_text.empty()) {
            status_text =
                std::string{i18n::tr(i18n::Key::LabelStatusOk)};
        }
    }
    if (!sync_ts) {
        return {};
    }
    return std::format(
        "{} ({})",
        platform::clock::format_local_timestamp(*sync_ts, false),
        status_text);
}

std::string format_overview_last_change(const OverviewProfileRow& row) {
    if (!row.activity.accepted_commit) {
        return {};
    }
    const auto& c = *row.activity.accepted_commit;
    const std::int64_t commit_ts =
        c.created_at > 0 ? c.created_at : c.accepted_at;
    const auto ts_str = platform::clock::format_local_timestamp(commit_ts, false);
    std::string author = sanitize_terminal_text(c.machine_name);
    if (author.empty() && !c.machine_id_hex.empty()) {
        author = sanitize_terminal_text(c.machine_id_hex.substr(0, 8));
    }
    if (!author.empty()) {
        return i18n::format(i18n::Key::OverviewLastChangeBy, ts_str, author);
    }
    return ts_str;
}

void print_profile_block_header(std::string_view name,
                                std::string_view state_label,
                                std::string_view tag,
                                bool use_color,
                                std::string_view color) {
    const std::string inner =
        tag.empty() ? std::string{state_label}
                    : std::format("{}, {}", state_label, tag);
    if (use_color && !color.empty()) {
        std::println("{} {}[{}]{}",
                     sanitize_terminal_text(name),
                     color,
                     inner,
                     style::reset);
    } else {
        std::println("{} [{}]", sanitize_terminal_text(name), inner);
    }
}

} // namespace

int present_overview(const application::DaemonStatusReport& daemon,
                     const std::vector<OverviewProfileRow>& rows,
                     bool full,
                     bool quiet) {
    if (quiet) {
        return 0;
    }
    if (rows.empty()) {
        i18n::println(i18n::Key::OverviewQuickstartHeader);
        return 0;
    }
    if (daemon.running) {
        if (daemon.autostart.supported) {
            i18n::println(
                i18n::Key::OverviewDaemonRunning,
                daemon.autostart.installed
                    ? i18n::tr(i18n::Key::OverviewAutostartOn)
                    : i18n::tr(i18n::Key::OverviewAutostartOff));
        } else {
            i18n::println(i18n::Key::OverviewDaemonRunningNoAutostart);
        }
        if (full) {
            i18n::println(
                i18n::Key::DaemonStatusPidPort, daemon.pid, daemon.ipc_port);
            i18n::println(i18n::Key::DaemonStatusUptime, daemon.uptime_seconds);
        }
    } else {
        i18n::println(i18n::Key::OverviewDaemonStopped);
    }
    std::println("");

    const bool use_color = platform::stdout_terminal().ansi;
    for (std::size_t idx = 0; idx < rows.size(); ++idx) {
        if (idx > 0U) {
            std::println("");
        }
        const auto& row = rows[idx];
        const auto& name = row.profile.name;
        std::string_view badge = i18n::tr(i18n::Key::OverviewBadgeReady);
        std::string_view color;
        std::optional<i18n::Key> alert_key;
        std::string alert_value;

        const bool daemon_syncing =
            daemon.running && row.daemon_profile &&
            row.daemon_profile->state ==
                application::DaemonProfileState::RunningSync;

        if (daemon_syncing) {
            badge = i18n::tr(i18n::Key::OverviewBadgeSyncing);
            color = style::cyan;
            alert_key = i18n::Key::OverviewLineStage;
            alert_value = format_active_stage_progress(*row.daemon_profile, full);
        } else if (row.conflict_count > 0) {
            badge = i18n::tr(i18n::Key::OverviewBadgeConflict);
            color = style::yellow;
            alert_key = i18n::Key::OverviewLineConflicts;
            alert_value = i18n::format(i18n::Key::OverviewDetailConflicts,
                                       row.conflict_count,
                                       sanitize_terminal_text(name));
        } else if (daemon.running && row.daemon_profile) {
            using S = application::DaemonProfileState;
            switch (row.daemon_profile->state) {
                case S::Paused:
                    badge = i18n::tr(i18n::Key::OverviewBadgePaused);
                    color = style::yellow;
                    break;
                case S::Locked:
                    badge = i18n::tr(i18n::Key::OverviewBadgeLocked);
                    color = style::yellow;
                    alert_key = i18n::Key::OverviewLineAction;
                    alert_value = i18n::format(
                        i18n::Key::OverviewDetailUnlockHint,
                        sanitize_terminal_text(name));
                    break;
                case S::NeedsAttention:
                    badge = i18n::tr(i18n::Key::OverviewBadgeError);
                    color = style::red;
                    alert_key = i18n::Key::OverviewLineError;
                    alert_value = row.daemon_profile->last_error.empty()
                                      ? std::string{overview_problem_message(
                                            row.local_problem)}
                                      : sanitize_terminal_text(
                                            row.daemon_profile->last_error);
                    break;
                case S::Backoff:
                    badge = i18n::tr(i18n::Key::OverviewBadgeRetrying);
                    color = style::yellow;
                    alert_key = i18n::Key::OverviewLineError;
                    alert_value = sanitize_terminal_text(
                        row.daemon_profile->last_error);
                    break;
                case S::PendingDebounce:
                    badge = i18n::tr(i18n::Key::OverviewBadgePending);
                    color = style::cyan;
                    alert_key = i18n::Key::OverviewLinePending;
                    alert_value = i18n::format(
                        i18n::Key::OverviewDetailLocalChanges,
                        (std::max)(row.daemon_profile->dirty_paths_count,
                                   std::size_t{1}));
                    break;
                case S::RunningSync:
                    badge = i18n::tr(i18n::Key::OverviewBadgeSyncing);
                    color = style::cyan;
                    alert_key = i18n::Key::OverviewLineStage;
                    alert_value =
                        format_active_stage_progress(*row.daemon_profile, full);
                    break;
                case S::Idle:
                    if (row.local_state ==
                        application::ProfileLocalState::Problem) {
                        badge = i18n::tr(i18n::Key::OverviewBadgeError);
                        color = style::red;
                        alert_key = i18n::Key::OverviewLineError;
                        alert_value = std::string{
                            overview_problem_message(row.local_problem)};
                    }
                    break;
            }
        } else {
            if (row.profile.paused) {
                badge = i18n::tr(i18n::Key::OverviewBadgePaused);
                color = style::yellow;
            } else if (row.local_state ==
                       application::ProfileLocalState::Problem) {
                badge = i18n::tr(i18n::Key::OverviewBadgeError);
                color = style::red;
                alert_key = i18n::Key::OverviewLineError;
                alert_value =
                    std::string{overview_problem_message(row.local_problem)};
            } else if (!row.activity.database_present) {
                badge = i18n::tr(i18n::Key::OverviewBadgeReady);
                alert_key = i18n::Key::OverviewLineAction;
                alert_value = i18n::format(i18n::Key::OverviewDetailNeedsInitial,
                                           sanitize_terminal_text(name));
            }
        }

        const bool is_paused =
            (daemon.running && row.daemon_profile &&
             row.daemon_profile->state == application::DaemonProfileState::Paused) ||
            (!daemon.running && row.profile.paused);
        const bool is_locked =
            daemon.running && row.daemon_profile &&
            row.daemon_profile->state == application::DaemonProfileState::Locked;
        std::string_view tag;
        if (!is_paused && !is_locked) {
            const bool watch_off =
                row.daemon_profile ? !row.daemon_profile->watch_enabled
                                   : !row.profile.watch_enabled.value_or(true);
            const std::uint32_t sync_interval =
                row.daemon_profile
                    ? row.daemon_profile->sync_interval_seconds
                    : row.profile.sync_interval_seconds.value_or(300U);
            if (watch_off) {
                tag = sync_interval == 0U
                          ? i18n::tr(i18n::Key::OverviewTagManualOnly)
                          : i18n::tr(i18n::Key::OverviewTagWatchOff);
            }
        }

        print_profile_block_header(name, badge, tag, use_color, color);

        if (full) {
            i18n::println(i18n::Key::OverviewLineLocal,
                          sanitize_terminal_text(
                              platform::path::to_utf8(row.profile.local_dir)));
            i18n::println(i18n::Key::OverviewLineRemote,
                          sanitize_terminal_text(row.profile.remote_dir));
        }
        if (alert_key.has_value() && !alert_value.empty()) {
            i18n::println(*alert_key, alert_value);
        }
        const auto last_sync = format_overview_last_sync(row);
        if (!last_sync.empty()) {
            i18n::println(i18n::Key::OverviewLineLastSync, last_sync);
        } else if (!alert_key.has_value()) {
            i18n::println(i18n::Key::OverviewLineLastSync,
                          i18n::tr(i18n::Key::OverviewDetailNeverSynced));
        }
        const auto last_change = format_overview_last_change(row);
        if (!last_change.empty()) {
            i18n::println(i18n::Key::OverviewLineLastChange, last_change);
        }
        if (full && row.daemon_profile) {
            const auto& p = *row.daemon_profile;
            i18n::println(
                i18n::Key::OverviewLineDaemon,
                std::format("{} | watch: {} | interval: {} | dirty: {}",
                            application::to_string(p.state),
                            format_watch_label(p),
                            format_sync_interval_label(p.sync_interval_seconds),
                            p.dirty_paths_count));
            i18n::println(
                i18n::Key::OverviewLineResult,
                std::format("{} (failures: {}, backoff: {}s)",
                            p.last_outcome.empty()
                                ? std::string{"-"}
                                : sanitize_terminal_text(p.last_outcome),
                            p.consecutive_failures,
                            p.backoff_seconds));
        }
    }
    if (!full) {
        std::println("");
        i18n::println(i18n::Key::OverviewFullHint);
    }
    return 0;
}

int present(const application::DaemonStatusReport& report,
            bool full,
            bool quiet) {
    if (quiet) {
        return 0;
    }
    const auto yes_no_str = [](bool v) {
        return v ? i18n::tr(i18n::Key::LabelYes)
                 : i18n::tr(i18n::Key::LabelNo);
    };
    if (report.running) {
        i18n::println(i18n::Key::DaemonStatusHeader);
        if (full) {
            i18n::println(
                i18n::Key::DaemonStatusPidPort, report.pid, report.ipc_port);
        }
        i18n::println(i18n::Key::DaemonStatusUptime, report.uptime_seconds);
        if (full) {
            i18n::println(i18n::Key::DaemonStatusVersion,
                          report.kasumi_version.empty()
                              ? std::string{"-"}
                              : sanitize_terminal_text(report.kasumi_version),
                          report.api_version,
                          yes_no_str(report.secure_pages_locked));
        }
    } else {
        i18n::println(i18n::Key::DaemonStatusOffline);
    }
    if (report.autostart.supported) {
        i18n::println(i18n::Key::DaemonStatusAutostart,
                      yes_no_str(report.autostart.installed),
                      sanitize_terminal_text(report.autostart.method));
    }
    if (report.profiles.empty()) {
        i18n::println(i18n::Key::DaemonStatusProfilesNone);
        return 0;
    }

    std::println("");
    for (std::size_t idx = 0; idx < report.profiles.size(); ++idx) {
        if (idx > 0U) {
            std::println("");
        }
        const auto& p = report.profiles[idx];
        i18n::println(i18n::Key::DaemonStatusProfileEntry,
                      sanitize_terminal_text(p.name),
                      application::to_string(p.state));
        if (!full) {
            if (!p.active_stage.empty()) {
                i18n::println(i18n::Key::OverviewLineStage,
                              format_active_stage_progress(p, true));
            }
            if (!p.last_error.empty()) {
                i18n::println(i18n::Key::DaemonStatusProfileError,
                              sanitize_terminal_text(p.last_error));
            }
            if (p.last_sync_finished_at.has_value()) {
                const auto ts_str = platform::clock::format_local_timestamp(
                    *p.last_sync_finished_at, false);
                const auto val =
                    p.last_outcome.empty()
                        ? ts_str
                        : std::format("{} ({})",
                                      ts_str,
                                      sanitize_terminal_text(p.last_outcome));
                i18n::println(i18n::Key::OverviewLineLastSync, val);
            } else if (p.active_stage.empty() && p.last_error.empty()) {
                i18n::println(i18n::Key::OverviewLineLastSync,
                              i18n::tr(i18n::Key::OverviewDetailNeverSynced));
            }
            continue;
        }

        i18n::println(i18n::Key::OverviewLineLocal,
                      sanitize_terminal_text(p.local_dir));
        i18n::println(i18n::Key::OverviewLineRemote,
                      sanitize_terminal_text(p.remote_dir));
        i18n::println(i18n::Key::DaemonStatusProfileWatch,
                      format_watch_label(p),
                      format_sync_interval_label(p.sync_interval_seconds),
                      p.dirty_paths_count);
        i18n::println(i18n::Key::DaemonStatusProfileSession,
                      yes_no_str(p.warm_transport_active),
                      p.warm_cache_entries);
        i18n::println(i18n::Key::DaemonStatusProfileCounters,
                      p.sync_runs,
                      p.fast_noop_polls,
                      p.consecutive_failures,
                      p.backoff_seconds);
        if (p.last_sync_finished_at.has_value() || !p.last_outcome.empty()) {
            const std::string ts_str =
                p.last_sync_finished_at.has_value()
                    ? platform::clock::format_local_timestamp(
                          *p.last_sync_finished_at, false)
                    : std::string{"-"};
            const std::string val =
                p.last_outcome.empty()
                    ? ts_str
                    : std::format("{} ({})",
                                  ts_str,
                                  sanitize_terminal_text(p.last_outcome));
            i18n::println(i18n::Key::OverviewLineLastSync, val);
        }
        if (!p.active_stage.empty()) {
            i18n::println(i18n::Key::OverviewLineStage,
                          format_active_stage_progress(p, true));
        }
        if (!p.last_error.empty()) {
            i18n::println(i18n::Key::DaemonStatusProfileError,
                          sanitize_terminal_text(p.last_error));
        }
    }
    return 0;
}

int present(const application::DaemonAutostartStatus& status, bool quiet) {
    if (quiet) {
        return 0;
    }
    if (!status.supported) {
        i18n::println(i18n::Key::DaemonAutostartUnsupported,
                      sanitize_terminal_text(status.detail));
        return 0;
    }
    i18n::println(i18n::Key::DaemonAutostartHeader,
                  status.installed ? i18n::tr(i18n::Key::LabelYes)
                                   : i18n::tr(i18n::Key::LabelNo),
                  sanitize_terminal_text(status.method));
    if (!status.location.empty()) {
        std::println("  location={}", sanitize_terminal_text(status.location));
    }
    if (!status.command.empty()) {
        std::println("  command={}", sanitize_terminal_text(status.command));
    }
    if (!status.detail.empty()) {
        std::println("  detail={}", sanitize_terminal_text(status.detail));
    }
    return 0;
}

int present(const application::DaemonSyncTriggerReport& report,
            bool wait,
            bool quiet) {
    const int exit_code = report.failures.empty() ? 0 : 1;
    if (!quiet) {
        if (wait) {
            print_ok_line(i18n::format(i18n::Key::DaemonSyncCompleted,
                                       report.profiles.size()));
        } else {
            print_ok_line(i18n::format(i18n::Key::DaemonSyncTriggered,
                                       report.profiles.size()));
        }
    }
    for (const auto& [pname, err] : report.failures) {
        print_error_line(i18n::format(i18n::Key::DaemonSyncFailed,
                                      sanitize_terminal_text(pname),
                                      sanitize_terminal_text(err)));
    }
    return exit_code;
}

bool is_noisy_daemon_event(const application::DaemonEvent& event) noexcept {
    return event.kind == "fast_noop" ||
           event.kind == "warm_transport_opened" ||
           event.kind == "warm_transport_closed";
}

void print_daemon_event_line(const application::DaemonEvent& ev) {
    const std::string ts =
        platform::clock::format_local_timestamp(ev.timestamp_unix);
    const std::string_view scope = ev.profile_name.empty()
                                       ? std::string_view{"daemon"}
                                       : std::string_view{ev.profile_name};
    i18n::println(i18n::Key::DaemonLogsEntry,
                  ts,
                  sanitize_terminal_text(scope),
                  sanitize_terminal_text(ev.kind),
                  sanitize_terminal_text(ev.detail));
}

int present(const application::DaemonLogsReport& report,
            bool full,
            bool quiet) {
    if (quiet) {
        return 0;
    }
    i18n::println(i18n::Key::DaemonLogsHeader,
                  sanitize_terminal_text(report.log_path));
    bool printed = false;
    for (const auto& ev : report.events) {
        if (!full && is_noisy_daemon_event(ev)) {
            continue;
        }
        print_daemon_event_line(ev);
        printed = true;
    }
    if (!printed) {
        i18n::println(i18n::Key::DaemonLogsEmpty);
    }
    return 0;
}

int present(const application::DaemonError& error) {
    print_error_line(sanitize_terminal_text(error.detail));
    if (error.code == application::DaemonErrorCode::NotRunning) {
        i18n::println(i18n::Key::DaemonStartHint);
    }
    return 1;
}

} // namespace kasumi::cli
