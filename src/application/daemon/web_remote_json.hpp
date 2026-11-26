#pragma once

#include "application/inspection/result.hpp"

#include <nlohmann/json.hpp>

namespace kasumi::application {
NLOHMANN_JSON_SERIALIZE_ENUM(RemoteCommitOrigin,
                             {{RemoteCommitOrigin::Unknown, "unknown"},
                              {RemoteCommitOrigin::Sync, "sync"},
                              {RemoteCommitOrigin::Repack, "repack"},
                              {RemoteCommitOrigin::ResolveMissing,
                               "resolve_missing"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteCommitAuthorship,
                                                  operation,
                                                  machine_id_hex,
                                                  machine_name)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteHeadInfo,
                                                  commit_id,
                                                  height,
                                                  created_at,
                                                  parent_ids,
                                                  root_hash,
                                                  file_count,
                                                  directory_count,
                                                  total_bytes,
                                                  authorship)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteHeadsReport,
                                                  history_present,
                                                  observed_height,
                                                  physical_marker_count,
                                                  ancestral_marker_count,
                                                  heads)

NLOHMANN_JSON_SERIALIZE_ENUM(RemoteTreeEntryType,
                             {{RemoteTreeEntryType::File, "file"},
                              {RemoteTreeEntryType::Directory, "directory"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(
    RemoteTreeEntry, path, type, logical_hash, size)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteTreeReport,
                                                  history_present,
                                                  commit_id,
                                                  height,
                                                  created_at,
                                                  root_hash,
                                                  total_bytes,
                                                  file_count,
                                                  directory_count,
                                                  entries)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteCommitInfo,
                                                  commit_id,
                                                  height,
                                                  created_at,
                                                  parent_ids,
                                                  logical_head,
                                                  physically_marked,
                                                  ancestral_marked,
                                                  root_hash,
                                                  total_bytes,
                                                  entry_count,
                                                  authorship)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteCommitsReport,
                                                  history_present,
                                                  observed_height,
                                                  logical_head_ids,
                                                  commits)

NLOHMANN_JSON_SERIALIZE_ENUM(
    RemoteActivityOperation,
    {{RemoteActivityOperation::Fsck, "fsck"},
     {RemoteActivityOperation::GarbageCollect, "garbage_collect"},
     {RemoteActivityOperation::RemoveWriter, "remove_writer"},
     {RemoteActivityOperation::RemoveBarrier, "remove_barrier"}})

NLOHMANN_JSON_SERIALIZE_ENUM(RemoteActivityOutcome,
                             {{RemoteActivityOutcome::Succeeded, "succeeded"},
                              {RemoteActivityOutcome::IssuesFound,
                               "issues_found"},
                              {RemoteActivityOutcome::Blocked, "blocked"},
                              {RemoteActivityOutcome::Cancelled, "cancelled"},
                              {RemoteActivityOutcome::Failed, "failed"},
                              {RemoteActivityOutcome::Uncertain, "uncertain"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteActivityInfo,
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
                                                  detail)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteSpaceUsage,
                                                  current_content_bytes,
                                                  retained_content_bytes,
                                                  orphan_content_bytes,
                                                  unknown_sizes)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteSummaryReport,
                                                  history_present,
                                                  observed_height,
                                                  reachable_commit_count,
                                                  logical_head_count,
                                                  has_conflicts,
                                                  missing_content_count,
                                                  orphan_content_count,
                                                  active_writer_count,
                                                  recent_activities,
                                                  invalid_activity_count,
                                                  space_usage)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteChunkInfo, hash, size)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteStatReport,
                                                  observed_height,
                                                  has_conflicts,
                                                  commit_id,
                                                  path,
                                                  type,
                                                  logical_hash,
                                                  size,
                                                  modified_at_unix_nanoseconds,
                                                  pack_hash,
                                                  chunks)

NLOHMANN_JSON_SERIALIZE_ENUM(
    RemoteCommitVariantState,
    {{RemoteCommitVariantState::Valid, "valid"},
     {RemoteCommitVariantState::InvalidCiphertext, "invalid_ciphertext"},
     {RemoteCommitVariantState::InvalidCommit, "invalid_commit"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteCommitVariantInfo,
                                                  ciphertext_id,
                                                  object_identifier,
                                                  state)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteCommitReport,
                                                  commit,
                                                  variants)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteEpochAnchorInfo,
                                                  commit_id,
                                                  height)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteEpochInfo,
                                                  vault_id,
                                                  sequence,
                                                  epoch_id,
                                                  issued_at,
                                                  min_history_depth,
                                                  min_history_age_hours,
                                                  anchors,
                                                  previous_epoch_id,
                                                  next_epoch_id)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteEpochsReport, epochs)

NLOHMANN_JSON_SERIALIZE_ENUM(RemoteObjectCategory,
                             {{RemoteObjectCategory::Content, "content"},
                              {RemoteObjectCategory::CommitVariant,
                               "commit_variant"},
                              {RemoteObjectCategory::HeadMarker, "head_marker"},
                              {RemoteObjectCategory::Epoch, "epoch"},
                              {RemoteObjectCategory::Writer, "writer"},
                              {RemoteObjectCategory::Barrier, "barrier"},
                              {RemoteObjectCategory::Protocol, "protocol"},
                              {RemoteObjectCategory::Activity, "activity"},
                              {RemoteObjectCategory::Unknown, "unknown"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(
    RemoteObjectInfo, identifier, category, structurally_valid, relation)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteObjectsReport,
                                                  unknown_count,
                                                  objects)

NLOHMANN_JSON_SERIALIZE_ENUM(
    RemoteOrphanKind,
    {{RemoteOrphanKind::Commit, "commit"},
     {RemoteOrphanKind::CommitVariant, "commit_variant"},
     {RemoteOrphanKind::RedundantVariant, "redundant_variant"},
     {RemoteOrphanKind::InvalidVariant, "invalid_variant"},
     {RemoteOrphanKind::Content, "content"},
     {RemoteOrphanKind::ProtectedEpoch, "protected_epoch"},
     {RemoteOrphanKind::Unknown, "unknown"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteOrphanInfo,
                                                  identifier,
                                                  kind,
                                                  removal_candidate)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteOrphansReport, objects)

NLOHMANN_JSON_SERIALIZE_ENUM(RemoteWriterState,
                             {{RemoteWriterState::Indeterminate,
                               "indeterminate"},
                              {RemoteWriterState::Invalid, "invalid"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(
    RemoteWriterInfo, identifier, state, machine_name, pid, started_at_unix)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteBarrierInfo,
                                                  identifier,
                                                  legacy,
                                                  structurally_valid,
                                                  machine_name,
                                                  pid,
                                                  started_at_unix)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteWritersReport,
                                                  barrier_present,
                                                  barrier_identifier,
                                                  maintenance_blocked,
                                                  protocol_consistent,
                                                  barriers,
                                                  writers)

NLOHMANN_JSON_SERIALIZE_ENUM(RemoteHealthState,
                             {{RemoteHealthState::Healthy, "healthy"},
                              {RemoteHealthState::Degraded, "degraded"},
                              {RemoteHealthState::Critical, "critical"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteHealthReport,
                                                  state,
                                                  marker_count,
                                                  reachable_commit_count,
                                                  orphan_count,
                                                  missing_content_count,
                                                  invalid_content_count,
                                                  writer_count,
                                                  unknown_object_count,
                                                  reasons)

NLOHMANN_JSON_SERIALIZE_ENUM(RemotePathChangeKind,
                             {{RemotePathChangeKind::Added, "added"},
                              {RemotePathChangeKind::Modified, "modified"},
                              {RemotePathChangeKind::Deleted, "deleted"},
                              {RemotePathChangeKind::Observed, "observed"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteLogEntry,
                                                  commit_id,
                                                  height,
                                                  created_at,
                                                  logical_head,
                                                  change,
                                                  type,
                                                  logical_hash,
                                                  size,
                                                  modified_at_unix_nanoseconds,
                                                  authorship)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(
    RemoteLogReport, path, observed_height, present_in_current_tree, entries)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RemoteRestoreReport,
                                                  dry_run,
                                                  commit_id,
                                                  observed_height,
                                                  source_prefix,
                                                  destination_path,
                                                  file_count,
                                                  directory_count,
                                                  total_bytes)
} // namespace kasumi::application
