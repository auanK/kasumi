#include "application/daemon/fast_poll.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/file_metadata.hpp"
#include "application/sync/journal.hpp"
#include "platform/path.hpp"
#include "platform/profile_lock.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <filesystem>
#include <optional>
#include <system_error>
#include <tuple>
#include <vector>

namespace kasumi::application::daemon_detail {
namespace {

bool journal_evidence_present(const std::filesystem::path& profile_dir) {
    const auto paths = sync::journal::make_paths(profile_dir);
    if (!paths) {
        return true;
    }
    const auto check_absent = [&](const std::filesystem::path& path) {
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(path, ec);
        return ec != std::errc::no_such_file_or_directory &&
               (ec || status.type() != std::filesystem::file_type::not_found);
    };
    if (check_absent(paths->final_path) ||
        check_absent(paths->final_path.parent_path())) {
        return true;
    }
    auto cleared_name = paths->final_path.filename().native();
    cleared_name += platform::path::from_utf8(".cleared").native();
    const auto cleared_path =
        paths->final_path.parent_path() / std::move(cleared_name);
    return check_absent(cleared_path);
}

bool ignore_stamp_matches(
    const std::filesystem::path& local_dir,
    bool expected_present,
    const observation::DatabaseMetadataStamp& expected_stamp) {
    const auto ignore_path = local_dir / ".kasumiignore";
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(ignore_path, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        (!ec && status.type() == std::filesystem::file_type::not_found)) {
        return !expected_present;
    }
    if (ec || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status) || !expected_present) {
        return false;
    }
    const auto utf8 = platform::path::to_utf8(ignore_path);
    const auto meta = observation::cache::read_file_metadata(ignore_path, utf8);
    if (!meta || !meta->has_value() || !(*meta)->identity.has_value()) {
        return false;
    }
    const auto& m = **meta;
    return expected_stamp.present && expected_stamp.size == m.size &&
           expected_stamp.mtime_ns == m.mtime_nanoseconds &&
           expected_stamp.volume == m.identity->volume &&
           expected_stamp.file_low == m.identity->file_low &&
           expected_stamp.file_high == m.identity->file_high;
}

std::optional<history_storage::epoch::Reference>
parse_latest_epoch(const history_storage::RemoteLayout& layout,
                   const std::vector<std::string>& child_names,
                   bool& all_valid) {
    all_valid = true;
    std::optional<history_storage::epoch::Reference> latest;
    for (const auto& name : child_names) {
        const auto parsed = history_storage::parse_epoch_object(
            layout, layout.epochs_prefix + name);
        if (!parsed) {
            all_valid = false;
            return std::nullopt;
        }
        if (!latest || std::tie(latest->sequence, latest->epoch_id) <
                           std::tie(parsed->sequence, parsed->epoch_id)) {
            latest = *parsed;
        }
    }
    return latest;
}

} // namespace

FastPollReport try_fast_remote_noop_poll(
    const ExecutionEnvironment& environment,
    std::string_view profile_name,
    const runtime::RuntimeData& runtime_data,
    transport::Transport& borrowed_transport,
    std::span<const std::uint8_t, 32> master_key,
    observation::LocalObservationSession& warm_observation,
    bool ignore_file_present,
    const observation::DatabaseMetadataStamp& expected_ignore_stamp) {
    if (!transport::valid(borrowed_transport)) {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = "warm transport unavailable"};
    }
    if (!ignore_stamp_matches(runtime_data.local_dir,
                              ignore_file_present,
                              expected_ignore_stamp)) {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = ".kasumiignore changed"};
    }

    auto lock = platform::acquire_profile_lock(
        environment.app_data_dir /
        ("profile-" + std::string{profile_name} + ".lock"));
    if (!lock) {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = lock.error(),
                .profile_locked = true};
    }
    struct LockGuard {
        std::intptr_t handle;
        ~LockGuard() noexcept {
            platform::release_profile_lock(handle);
        }
    } lock_guard{*lock};

    if (!observation::warm_session_db_matches(warm_observation,
                                              runtime_data.database_path)) {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = "local database modified externally"};
    }
    if (journal_evidence_present(runtime_data.database_path.parent_path())) {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = "pending transaction journal"};
    }
    if (!state_storage::validate(runtime_data.database_path)) {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = "database validation failed"};
    }
    const auto persisted =
        state_storage::load_state(runtime_data.database_path);
    if (!persisted || !persisted->has_value()) {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = "no accepted local commit yet"};
    }
    // validate() may open READWRITE to clear stale WAL recovery state on a
    // quiescent DB; refresh our warm DB stamp under the profile lock so the
    // next fast poll does not mistake our own read for external modification.
    observation::refresh_warm_session_db_stamp(warm_observation,
                                               runtime_data.database_path);
    const auto& state = **persisted;
    if (state.commit_id.empty() || state.ciphertext_id.empty() ||
        !state.pending_materializations.empty()) {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = "incomplete local accepted state"};
    }

    const auto layout = history_storage::derive_remote_layout(master_key);
    const std::string heads_dir{
        history_storage::detail::trim_trailing_slash(layout.heads_prefix)};
    const std::string epochs_dir{
        history_storage::detail::trim_trailing_slash(layout.epochs_prefix)};

    std::vector<std::string> heads;
    std::vector<std::string> epochs;

    transport::ControlReadBatchRequest batch_req{
        .list_prefixes = {heads_dir, epochs_dir},
        .presence_identifiers = {},
    };
    auto batch = transport::control_read_batch(borrowed_transport, batch_req);
    if (batch) {
        if (batch->listings.size() != 2U) {
            return {.verdict = FastPollVerdict::FullSyncRequired,
                    .reason = "incomplete control read response",
                    .transport_error = true};
        }
        heads = std::move(batch->listings[0]);
        epochs = std::move(batch->listings[1]);
    } else if (batch.error().code == transport::ErrorCode::Unsupported) {
        auto h = history_storage::detail::list_identifiers(borrowed_transport,
                                                           heads_dir);
        if (!h) {
            return {.verdict = FastPollVerdict::FullSyncRequired,
                    .reason = h.error().detail,
                    .transport_error = true};
        }
        auto e = history_storage::detail::list_identifiers(borrowed_transport,
                                                           epochs_dir);
        if (!e) {
            return {.verdict = FastPollVerdict::FullSyncRequired,
                    .reason = e.error().detail,
                    .transport_error = true};
        }
        heads = std::move(*h);
        epochs = std::move(*e);
    } else {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = transport::describe(batch.error()),
                .transport_error = true};
    }

    const std::string expected_marker =
        state.commit_id + "-" + state.ciphertext_id;
    if (heads.size() != 1U || heads.front() != expected_marker) {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = "remote head markers changed"};
    }

    bool epochs_valid = true;
    const auto latest_epoch = parse_latest_epoch(layout, epochs, epochs_valid);
    if (!epochs_valid) {
        return {.verdict = FastPollVerdict::FullSyncRequired,
                .reason = "unrecognized remote epoch object"};
    }
    if (state.epoch_id.empty()) {
        if (latest_epoch.has_value()) {
            return {.verdict = FastPollVerdict::FullSyncRequired,
                    .reason = "new remote epoch created"};
        }
    } else {
        if (!latest_epoch.has_value() ||
            latest_epoch->sequence != state.epoch_sequence ||
            latest_epoch->epoch_id != state.epoch_id) {
            return {.verdict = FastPollVerdict::FullSyncRequired,
                    .reason = "remote epoch advanced or diverged"};
        }
    }

    return {.verdict = FastPollVerdict::NoChanges,
            .reason = "remote unchanged"};
}

} // namespace kasumi::application::daemon_detail
