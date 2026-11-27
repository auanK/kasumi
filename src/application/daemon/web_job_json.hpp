#pragma once

#include "application/execute.hpp"
#include "application/result.hpp"

#include <nlohmann/json.hpp>

namespace kasumi::application {
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(SyncCompleted,
                                                  total,
                                                  uploaded,
                                                  downloaded,
                                                  removed,
                                                  renamed,
                                                  copied,
                                                  created_dirs,
                                                  removed_dirs,
                                                  repaired,
                                                  upload_bytes,
                                                  download_bytes,
                                                  published,
                                                  pending,
                                                  pending_paths,
                                                  partial,
                                                  wire_upload_bytes,
                                                  wire_download_bytes,
                                                  local_delta_reused_bytes,
                                                  physical_objects_uploaded,
                                                  physical_objects_downloaded)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(InventoryAuditReport,
                                                  referenced_content,
                                                  present_content,
                                                  missing_content,
                                                  orphan_content,
                                                  unknown_objects)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(ManualWriterRemovalCompleted,
                                                  identifier,
                                                  removed_identifiers,
                                                  already_absent_identifiers)

NLOHMANN_JSON_SERIALIZE_ENUM(BarrierRemovalOutcome,
                             {{BarrierRemovalOutcome::Removed, "removed"},
                              {BarrierRemovalOutcome::AlreadyAbsent,
                               "already_absent"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(ManualBarrierRemovalCompleted,
                                                  identifier,
                                                  outcome,
                                                  active_writers_count,
                                                  remaining_barriers_count)

NLOHMANN_JSON_SERIALIZE_ENUM(
    BarrierRemovalStage,
    {{BarrierRemovalStage::CheckingPresence, "checking_presence"},
     {BarrierRemovalStage::DownloadingPayload, "downloading_payload"},
     {BarrierRemovalStage::ValidatingPayload, "validating_payload"},
     {BarrierRemovalStage::CheckingWriters, "checking_writers"},
     {BarrierRemovalStage::VerifyingPhysicalIdentity,
      "verifying_physical_identity"},
     {BarrierRemovalStage::Removing, "removing"},
     {BarrierRemovalStage::ConfirmingAbsence, "confirming_absence"}})

NLOHMANN_JSON_SERIALIZE_ENUM(
    BarrierRemovalMutationState,
    {{BarrierRemovalMutationState::NotAttempted, "not_attempted"},
     {BarrierRemovalMutationState::Confirmed, "confirmed"},
     {BarrierRemovalMutationState::Uncertain, "uncertain"}})

NLOHMANN_JSON_SERIALIZE_ENUM(
    PlanAction,
    {{PlanAction::RenameLocal, "rename_local"},
     {PlanAction::Upload, "upload"},
     {PlanAction::CreateLocalDirectory, "create_local_directory"},
     {PlanAction::CreateRemoteDirectory, "create_remote_directory"},
     {PlanAction::MoveLocal, "move_local"},
     {PlanAction::Download, "download"},
     {PlanAction::DeleteLocal, "delete_local"},
     {PlanAction::DeleteLocalDirectory, "delete_local_directory"},
     {PlanAction::DeleteRemote, "delete_remote"},
     {PlanAction::DeleteRemoteDirectory, "delete_remote_directory"},
     {PlanAction::CopyLocal, "copy_local"},
     {PlanAction::DeleteIgnoredLocalFile, "delete_ignored_local_file"},
     {PlanAction::Count, "count"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(
    PlanItem, action, path, alternative_path, size)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(PlanReport,
                                                  target_generation,
                                                  action_counts,
                                                  upload_bytes,
                                                  download_bytes,
                                                  has_conflicts,
                                                  items,
                                                  pending_paths)

NLOHMANN_JSON_SERIALIZE_ENUM(SyncStage,
                             {{SyncStage::Observing, "observing"},
                              {SyncStage::Calculating, "calculating"},
                              {SyncStage::Applying, "applying"},
                              {SyncStage::Publishing, "publishing"},
                              {SyncStage::Finalizing, "finalizing"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(FsckCompleted,
                                                  checked_objects,
                                                  checked_plaintext_bytes,
                                                  wire_download_bytes,
                                                  physical_objects_downloaded,
                                                  files_reassembled)

NLOHMANN_JSON_SERIALIZE_ENUM(GarbageCollectStage,
                             {{GarbageCollectStage::Preparing, "preparing"},
                              {GarbageCollectStage::Analyzing, "analyzing"},
                              {GarbageCollectStage::Applying, "applying"},
                              {GarbageCollectStage::Finalizing, "finalizing"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(GarbageCollectCompleted,
                                                  candidate_objects,
                                                  analysis_only,
                                                  dry_run,
                                                  candidate_content_objects,
                                                  candidate_commit_variants,
                                                  candidate_expired_commits,
                                                  candidate_activities,
                                                  deferred_recent_objects,
                                                  candidate_bytes,
                                                  removed_objects,
                                                  removed_bytes,
                                                  min_age_hours)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(
    ResolveMissingCompleted, resolved_count, resolved_paths, published, dry_run)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(RepackCompleted,
                                                  dry_run,
                                                  actionable,
                                                  published,
                                                  live_small_blobs,
                                                  existing_packs,
                                                  healthy_packs_kept,
                                                  dirty_packs_detected,
                                                  loose_small_blobs_detected,
                                                  source_loose_blobs,
                                                  source_clean_packs,
                                                  source_dirty_packs,
                                                  new_packs,
                                                  repacked_blobs,
                                                  repacked_plaintext_bytes,
                                                  published_commit_id,
                                                  published_height,
                                                  pruned_markers,
                                                  wire_upload_bytes,
                                                  physical_objects_uploaded)

NLOHMANN_JSON_SERIALIZE_ENUM(
    Activity,
    {{Activity::Scanning, "scanning"},
     {Activity::Staging, "staging"},
     {Activity::Uploading, "uploading"},
     {Activity::Downloading, "downloading"},
     {Activity::Verifying, "verifying"},
     {Activity::Installing, "installing"},
     {Activity::Reobserving, "reobserving"},
     {Activity::Listing, "listing"},
     {Activity::Authenticating, "authenticating"},
     {Activity::Auditing, "auditing"},
     {Activity::Removing, "removing"},
     {Activity::ComparingSnapshots, "comparing_snapshots"},
     {Activity::CheckingRemoteContent, "checking_remote_content"},
     {Activity::PreparingPlan, "preparing_plan"},
     {Activity::PreparingRemote, "preparing_remote"},
     {Activity::CheckingControls, "checking_controls"},
     {Activity::EstablishingBarrier, "establishing_barrier"},
     {Activity::ProbingConsistency, "probing_consistency"},
     {Activity::AnalyzingReachability, "analyzing_reachability"},
     {Activity::LoadingActivities, "loading_activities"},
     {Activity::ReleasingBarrier, "releasing_barrier"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(ActivityProgress,
                                                  activity,
                                                  bytes,
                                                  total_bytes,
                                                  objects,
                                                  total_objects,
                                                  cache_hits,
                                                  files_hashed,
                                                  bytes_reused,
                                                  staged_bytes,
                                                  attempt,
                                                  observing_remote,
                                                  stage_id,
                                                  item_path,
                                                  item_bytes,
                                                  item_total_bytes)

NLOHMANN_JSON_SERIALIZE_ENUM(
    GarbageCollectSubStage,
    {{GarbageCollectSubStage::None, "none"},
     {GarbageCollectSubStage::CheckingControls, "checking_controls"},
     {GarbageCollectSubStage::EstablishingBarrier, "establishing_barrier"},
     {GarbageCollectSubStage::ProbingConsistency, "probing_consistency"},
     {GarbageCollectSubStage::ListingRemote, "listing_remote"},
     {GarbageCollectSubStage::AuthenticatingHistory, "authenticating_history"},
     {GarbageCollectSubStage::AnalyzingReachability, "analyzing_reachability"},
     {GarbageCollectSubStage::LoadingActivities, "loading_activities"},
     {GarbageCollectSubStage::RemovingObjects, "removing_objects"},
     {GarbageCollectSubStage::ReleasingBarrier, "releasing_barrier"}})

NLOHMANN_JSON_SERIALIZE_ENUM(FsckStage,
                             {{FsckStage::Preparing, "preparing"},
                              {FsckStage::Observing, "observing"},
                              {FsckStage::Analyzing, "analyzing"},
                              {FsckStage::AuditingContent, "auditing_content"},
                              {FsckStage::Finalizing, "finalizing"}})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(FsckProgress,
                                                  stage,
                                                  completed_objects,
                                                  total_objects,
                                                  completed_plaintext_bytes,
                                                  total_plaintext_bytes,
                                                  wire_download_bytes,
                                                  total_wire_bytes,
                                                  physical_objects_downloaded,
                                                  files_reassembled)
} // namespace kasumi::application
