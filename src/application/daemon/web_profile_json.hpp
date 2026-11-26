#pragma once

#include "application/daemon.hpp"
#include "application/profile.hpp"

#include <nlohmann/json.hpp>

namespace kasumi::application {
NLOHMANN_JSON_SERIALIZE_ENUM(KeyStorage,
                             {{KeyStorage::Vault, "vault"},
                              {KeyStorage::File, "file"},
                              {KeyStorage::Memory, "memory"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(Profile,
                                                  name,
                                                  local_dir,
                                                  remote_dir,
                                                  min_history_depth,
                                                  min_history_age_hours,
                                                  key_storage,
                                                  bandwidth_limit,
                                                  transfer_concurrency,
                                                  rclone_config,
                                                  watch_enabled,
                                                  sync_interval_seconds,
                                                  paused,
                                                  icon)

NLOHMANN_JSON_SERIALIZE_ENUM(ProfileLocalState,
                             {{ProfileLocalState::Initialized, "initialized"},
                              {ProfileLocalState::Ready, "ready"},
                              {ProfileLocalState::Pending, "pending"},
                              {ProfileLocalState::Running, "running"},
                              {ProfileLocalState::Problem, "problem"}})

NLOHMANN_JSON_SERIALIZE_ENUM(ProfileLocalProblem,
                             {{ProfileLocalProblem::None, "none"},
                              {ProfileLocalProblem::InvalidName,
                               "invalid_name"},
                              {ProfileLocalProblem::Paths, "paths"},
                              {ProfileLocalProblem::Directory, "directory"},
                              {ProfileLocalProblem::Key, "key"},
                              {ProfileLocalProblem::Database, "database"},
                              {ProfileLocalProblem::Lock, "lock"},
                              {ProfileLocalProblem::Sidecar, "sidecar"},
                              {ProfileLocalProblem::Journal, "journal"},
                              {ProfileLocalProblem::Workspace, "workspace"},
                              {ProfileLocalProblem::Snapshot, "snapshot"},
                              {ProfileLocalProblem::Cleanup, "cleanup"},
                              {ProfileLocalProblem::Count, "count"}})

NLOHMANN_JSON_SERIALIZE_ENUM(
    ProfileOperationKind,
    {{ProfileOperationKind::Sync, "sync"},
     {ProfileOperationKind::Fsck, "fsck"},
     {ProfileOperationKind::GarbageCollect, "garbage_collect"},
     {ProfileOperationKind::Repack, "repack"},
     {ProfileOperationKind::ResolveMissing, "resolve_missing"},
     {ProfileOperationKind::RemoveWriter, "remove_writer"},
     {ProfileOperationKind::RemoveBarrier, "remove_barrier"}})

NLOHMANN_JSON_SERIALIZE_ENUM(
    ProfileExecutionStatus,
    {{ProfileExecutionStatus::InProgress, "in_progress"},
     {ProfileExecutionStatus::Succeeded, "succeeded"},
     {ProfileExecutionStatus::SucceededNoChanges, "succeeded_no_changes"},
     {ProfileExecutionStatus::SucceededDownloadedOnly,
      "succeeded_downloaded_only"},
     {ProfileExecutionStatus::SucceededPartial, "succeeded_partial"},
     {ProfileExecutionStatus::IssuesFound, "issues_found"},
     {ProfileExecutionStatus::Blocked, "blocked"},
     {ProfileExecutionStatus::Cancelled, "cancelled"},
     {ProfileExecutionStatus::Failed, "failed"},
     {ProfileExecutionStatus::Uncertain, "uncertain"},
     {ProfileExecutionStatus::Interrupted, "interrupted"}})

NLOHMANN_JSON_SERIALIZE_ENUM(
    ProfileRemotePublishState,
    {{ProfileRemotePublishState::NotApplicable, "not_applicable"},
     {ProfileRemotePublishState::Published, "published"},
     {ProfileRemotePublishState::Pending, "pending"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(ProfileExecutionSummary,
                                                  execution_id,
                                                  operation,
                                                  machine_id_hex,
                                                  machine_name,
                                                  started_at,
                                                  finished_at,
                                                  duration_ms,
                                                  status,
                                                  recovered,
                                                  stage,
                                                  detail,
                                                  commit_id,
                                                  summary_a,
                                                  summary_b,
                                                  summary_c,
                                                  summary_bytes,
                                                  flags,
                                                  remote_publish_state)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(ProfileCommitAuthorship,
                                                  commit_id,
                                                  height,
                                                  created_at,
                                                  origin_operation,
                                                  machine_id_hex,
                                                  machine_name,
                                                  accepted_at)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(ProfileCachedRemoteActivity,
                                                  event_id,
                                                  operation,
                                                  outcome,
                                                  machine_id_hex,
                                                  machine_name,
                                                  started_at,
                                                  finished_at,
                                                  duration_ms,
                                                  metric_primary,
                                                  metric_secondary,
                                                  metric_bytes,
                                                  flags,
                                                  stage,
                                                  detail,
                                                  cached_at)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(ProfileActivityReport,
                                                  database_present,
                                                  accepted_commit,
                                                  last_attempt,
                                                  last_complete_sync,
                                                  recent_executions,
                                                  cached_remote_activities)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(DiagnosticsRcloneInfo,
                                                  found,
                                                  executable,
                                                  version,
                                                  minimum_version,
                                                  meets_minimum,
                                                  detail)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(ProfileDiagnostic,
                                                  profile,
                                                  local_state,
                                                  local_problem,
                                                  local_dir_exists,
                                                  local_dir_writable,
                                                  local_free_bytes,
                                                  local_capacity_bytes,
                                                  uses_rclone,
                                                  lock_active,
                                                  journal_present,
                                                  key_accessible,
                                                  healthy,
                                                  detail,
                                                  activity,
                                                  ignore_file_present,
                                                  ignore_file_valid,
                                                  ignore_error_line,
                                                  ignore_error_detail,
                                                  daemon_state,
                                                  daemon_active_stage,
                                                  daemon_watcher_active,
                                                  daemon_error)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(DiagnosticsDaemonInfo,
                                                  running,
                                                  pid,
                                                  ipc_port,
                                                  control_metadata_valid,
                                                  secure_pages_locked,
                                                  autostart_supported,
                                                  autostart_installed,
                                                  autostart_method,
                                                  detail)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(DiagnosticsReport,
                                                  os_name,
                                                  app_data_dir,
                                                  config_path,
                                                  config_exists,
                                                  app_data_free_bytes,
                                                  rclone,
                                                  daemon,
                                                  profiles,
                                                  overall_ok)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RcloneRemotesInfo,
                                                  available,
                                                  remotes,
                                                  detail)

NLOHMANN_JSON_SERIALIZE_ENUM(ConflictOrigin,
                             {{ConflictOrigin::Local, "local"},
                              {ConflictOrigin::Remote, "remote"},
                              {ConflictOrigin::BranchCommit, "branch_commit"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(
    LocalConflictArtifact, path, origin, origin_tag, size, modified_at)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(LocalConflictGroup,
                                                  canonical_path,
                                                  canonical_exists,
                                                  canonical_size,
                                                  canonical_modified_at,
                                                  artifacts)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(
    LocalConflictsReport, profile_name, local_dir, total_artifacts, groups)

NLOHMANN_JSON_SERIALIZE_ENUM(
    ConflictResolutionChoice,
    {{ConflictResolutionChoice::KeepCanonical, "keep_canonical"},
     {ConflictResolutionChoice::KeepArtifact, "keep_artifact"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(ResolveConflictReport,
                                                  profile_name,
                                                  canonical_path,
                                                  choice,
                                                  selected_artifact,
                                                  dry_run,
                                                  removed_artifacts)

NLOHMANN_JSON_SERIALIZE_ENUM(
    RemoteVaultState,
    {{RemoteVaultState::EmptyReadyForInit, "empty_ready_for_init"},
     {RemoteVaultState::AuthenticatedVault, "authenticated_vault"},
     {RemoteVaultState::KeyMismatchOrInvalidHistory,
      "key_mismatch_or_invalid_history"},
     {RemoteVaultState::TransportFailure, "transport_failure"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(ProfileConnectionReport,
                                                  profile_name,
                                                  remote_dir,
                                                  transport_ok,
                                                  ready,
                                                  vault_state,
                                                  head_count,
                                                  epoch_sequence,
                                                  epoch_id,
                                                  detail)

NLOHMANN_JSON_SERIALIZE_ENUM(
    IgnoreDispositionKind,
    {{IgnoreDispositionKind::Managed, "managed"},
     {IgnoreDispositionKind::IgnoredProtected, "ignored_protected"},
     {IgnoreDispositionKind::IgnoredDisposable, "ignored_disposable"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(IgnoreCheckItem,
                                                  input_path,
                                                  logical_path,
                                                  is_directory,
                                                  disposition,
                                                  reserved_internal,
                                                  matched_rule,
                                                  rule_line,
                                                  rule_text)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(
    IgnoreCheckReport, profile_name, ignore_file, ignore_file_present, items)

NLOHMANN_JSON_SERIALIZE_ENUM(IgnorePreset,
                             {{IgnorePreset::Default, "default"},
                              {IgnorePreset::Dev, "dev"},
                              {IgnorePreset::Office, "office"},
                              {IgnorePreset::Minimal, "minimal"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(IgnoreInitReport,
                                                  profile_name,
                                                  ignore_file,
                                                  preset,
                                                  created,
                                                  overwritten,
                                                  dry_run,
                                                  content)

NLOHMANN_JSON_SERIALIZE_ENUM(
    DaemonProfileState,
    {{DaemonProfileState::Idle, "idle"},
     {DaemonProfileState::PendingDebounce, "pending_debounce"},
     {DaemonProfileState::RunningSync, "running_sync"},
     {DaemonProfileState::Paused, "paused"},
     {DaemonProfileState::Locked, "locked"},
     {DaemonProfileState::Backoff, "backoff"},
     {DaemonProfileState::NeedsAttention, "needs_attention"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(
    DaemonEvent, seq, timestamp_unix, profile_name, kind, detail)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(DaemonAutostartStatus,
                                                  supported,
                                                  installed,
                                                  systemd_enabled,
                                                  method,
                                                  location,
                                                  command,
                                                  detail)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(DaemonProfileStatus,
                                                  name,
                                                  key_storage,
                                                  state,
                                                  paused,
                                                  locked,
                                                  watch_enabled,
                                                  watcher_active,
                                                  watcher_degraded,
                                                  warm_transport_active,
                                                  warm_cache_entries,
                                                  sync_interval_seconds,
                                                  local_dir,
                                                  remote_dir,
                                                  dirty_paths_count,
                                                  active_stage,
                                                  active_item_path,
                                                  active_item_bytes,
                                                  active_item_total_bytes,
                                                  active_objects,
                                                  active_total_objects,
                                                  active_bytes,
                                                  active_total_bytes,
                                                  sync_phase,
                                                  sync_applied_items,
                                                  sync_total_items,
                                                  active_bytes_per_second,
                                                  last_sync_started_at,
                                                  last_sync_finished_at,
                                                  last_checked_at,
                                                  next_sync_at,
                                                  backoff_until_unix,
                                                  backoff_seconds,
                                                  consecutive_failures,
                                                  sync_runs,
                                                  fast_noop_polls,
                                                  last_outcome,
                                                  last_error,
                                                  busy,
                                                  active_operation)
} // namespace kasumi::application
