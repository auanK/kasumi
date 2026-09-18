#ifndef KASUMI_CLI_I18N_HPP
#define KASUMI_CLI_I18N_HPP

#include <format>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kasumi::cli::i18n {

enum class Language {
    English,
    Portuguese,
    Custom,
};

enum class Key {
    // Labels
    LabelError,
    LabelWarning,
    LabelOk,
    LabelYes,
    LabelNo,
    LabelAncestralMarker,
    LabelAncestral,

    // Help Text
    HelpText,

    // Version
    VersionText,

    // Sync & Status
    SyncInProgress,
    SyncStarting,
    SyncStageObserving,
    SyncStageCalculating,
    SyncEverythingInSync,
    SyncChangesSingular,
    SyncChangesPlural,
    SyncCreatedDirSingular,
    SyncCreatedDirPlural,
    SyncRemovedDirSingular,
    SyncRemovedDirPlural,
    SyncStageApplying,
    SyncStagePublishing,
    SyncStageFinalizing,
    SyncCompleted,
    SyncNothingToDo,
    SyncPlanHeader,
    SyncPlanOmittedSingular,
    SyncPlanOmittedPlural,
    SyncConflictsWarning,
    SyncConflictsStatusHint,
    SyncSummaryHeader,
    SyncEstimatedTraffic,
    SyncUpload,
    SyncDownload,
    SyncCompletedWithDuration,
    SyncCancelledByUser,
    OperationCancelledByUser,
    SyncErrorObserving,
    SyncErrorCalculating,
    SyncErrorApplying,
    SyncErrorPublishing,
    SyncErrorFinalizing,
    SyncErrorReason,
    PreviewCompleted,
    PlanStageObserving,
    PlanStageCalculating,
    PreviewStarting,
    StatusStarting,

    // Operations / Errors
    ErrorPlanCalculation,
    ErrorFsckFailed,
    ErrorFsckClean,
    ErrorFsckAuditing,
    ErrorGcRunning,
    ErrorGcWarning,
    ErrorGcCancelled,
    ErrorGcCompleted,
    ErrorSyncFailed,
    ErrorInconsistentInspection,
    ErrorAvailableHeads,
    ErrorUseRemoteTreeHead,

    // Status / Inspection Headers & Details
    RemoteHeadsNone,
    RemoteHeadsHeader,
    RemoteTreeNone,
    RemoteTreeHead,
    RemoteTreeHeight,
    RemoteTreeFiles,
    RemoteTreeDirectories,
    RemoteTreeSize,
    RemoteCommitsNone,
    RemoteCommitsHeader,
    RemoteSummaryHeader,
    RemoteSummaryHistoryPresent,
    RemoteSummaryHistoryAbsent,
    RemoteStatHeader,
    RemoteStatView,
    RemoteStatDirectory,
    RemoteStatFile,
    RemoteCommitHeader,
    RemoteFileSavedHeader,
    RemoteEpochsHeader,
    RemoteEpochNone,
    RemoteEpochDetailHeader,
    RemoteContentsHeader,
    RemoteContentsDeepAudit,
    RemoteAuditHeader,
    RemoteContentHeader,
    RemoteMarkersHeader,
    RemoteObjectsHeader,
    RemoteOrphansHeader,
    RemoteOrphansReadOnlyHint,
    RemoteQuarantineHeader,
    RemoteQuarantineReadOnlyHint,
    RemoteWritersHeader,
    RemoteHealthHeader,

    // Inspection field labels
    FieldCommit,
    FieldHeight,
    FieldCreatedAt,
    FieldParents,
    FieldFiles,
    FieldDirectories,
    FieldSize,
    FieldRoot,
    FieldEntries,
    FieldLogicalHead,
    FieldPhysicalMarker,
    FieldAncestralMarker,
    FieldPhysicalVariants,
    FieldCiphertext,
    FieldObject,
    FieldState,
    FieldPath,
    FieldDestination,
    FieldLogicalHash,
    FieldSequence,
    FieldEpochId,
    FieldVaultId,
    FieldIssuedAt,
    FieldMinRetention,
    FieldPreviousEpoch,
    FieldNextEpoch,
    FieldAnchors,
    FieldType,
    FieldModifiedAt,
    FieldHistory,
    FieldReachableCommits,
    FieldLogicalHeads,
    FieldConflicts,
    FieldMissingContents,
    FieldOrphanContents,
    FieldActiveWriters,
    FieldParentsCount,
    FieldAnchorItem,
    FieldContentId,
    FieldReferenced,
    FieldPhysicallyPresent,
    FieldCurrentTree,
    FieldLogicalSize,
    FieldPathsCount,
    FieldPhysicalCount,
    FieldMissingCount,
    FieldOrphanCount,
    FieldValidCount,
    FieldInvalidCount,
    FieldAncestralsCount,
    FieldUnknownOrInvalid,
    FieldIdentifier,
    FieldCategory,
    FieldStructure,
    FieldStructureValid,
    FieldStructureInvalid,
    FieldRelation,
    FieldClassification,
    FieldStructuralCandidate,
    FieldOriginal,
    FieldQuarantine,
    FieldMetadata,
    FieldMetadataAuthenticated,
    FieldEnqueued,
    FieldRetentionElapsed,
    FieldBarrier,
    FieldPresent,
    FieldAbsent,
    FieldMaintenanceBlocked,
    FieldProtocolConsistent,
    FieldMarkers,
    FieldWriters,
    FieldUnknownObjects,
    FieldUnreachableObjects,
    FieldInvalidContents,
    FieldReasons,

    // Variant states
    VariantValid,
    VariantInvalidCiphertext,
    VariantInvalidCommit,
    VariantInvalid,

    // Content states
    ContentStatePresent,
    ContentStateMissing,
    ContentStateOrphan,
    ContentStateValid,
    ContentStateInvalid,
    ContentStateUnknown,

    // Marker states
    MarkerStateLogicalHead,
    MarkerStateAncestral,
    MarkerStateInvalidPath,
    MarkerStateMissing,
    MarkerStateInvalidMarker,
    MarkerStateMissingCommit,
    MarkerStateInvalidCiphertext,
    MarkerStateInvalidCommit,
    MarkerStateInvalid,

    // Object categories
    ObjectCategoryContent,
    ObjectCategoryCommitVariant,
    ObjectCategoryHeadMarker,
    ObjectCategoryEpoch,
    ObjectCategoryWriter,
    ObjectCategoryBarrier,
    ObjectCategoryQuarantine,
    ObjectCategoryRetentionMetadata,
    ObjectCategoryProtocol,
    ObjectCategoryUnknown,

    // Orphan kinds
    OrphanKindCommit,
    OrphanKindCommitVariant,
    OrphanKindRedundantVariant,
    OrphanKindInvalidVariant,
    OrphanKindContent,
    OrphanKindProtectedEpoch,
    OrphanKindUnknown,

    // Writer states
    WriterStateInvalid,
    WriterStateIndeterminate,

    // Health states
    HealthStateHealthy,
    HealthStateDegraded,
    HealthStateCritical,

    // Prompts / Credentials
    PromptPassword,
    PromptConfirmPassword,
    PromptSalt,
    PromptConfirmSalt,
    PasswordsDoNotMatch,
    SaltsDoNotMatch,

    // Wizard
    WizardHeader,
    WizardNoProfiles,
    WizardProfileListEntry,
    WizardMenu,
    WizardPromptProfileName,
    WizardProfileAlreadyExists,
    WizardPromptLocalPath,
    WizardPromptRemotePath,
    WizardLocalPathMustBeAbsolute,
    WizardRemotePathMustBeAbsolute,
    WizardProfileCreated,
    WizardProfileNotFound,
    WizardPromptProfileToDelete,
    WizardProfileDeleted,
    WizardPromptProfileToEdit,
    WizardPromptNewLocalPath,
    WizardPromptNewRemotePath,
    WizardProfileEdited,
    WizardPromptProfileToRename,
    WizardPromptNewProfileName,
    WizardProfileRenamed,
    WizardInvalidOption,
    WizardConfigReadFailed,
};

Language current_language() noexcept;

std::string_view current_language_code() noexcept;

void set_language(Language language);

void set_language(std::string_view code);

Language parse_language(std::string_view code) noexcept;

std::string_view language_code(Language language) noexcept;

std::string_view tr(Key key) noexcept;

bool load_custom_catalog(std::string_view json_content);

// Processes arguments, extracts and removes --lang <val> / --lang=<val>
// and returns the sanitized arguments without the language flag.
std::vector<std::string> extract_language_argument(int argc,
                                                   char* argv[]) noexcept;

// Initializes language from environment KASUMI_LANG or arguments.
void init_language(int argc, char* argv[]) noexcept;

template <typename... Args> inline std::string format(Key key, Args&&... args) {
    return std::vformat(tr(key), std::make_format_args(args...));
}

template <typename... Args> inline void println(Key key, Args&&... args) {
    std::println("{}", std::vformat(tr(key), std::make_format_args(args...)));
}

template <typename... Args> inline void print(Key key, Args&&... args) {
    std::print("{}", std::vformat(tr(key), std::make_format_args(args...)));
}

} // namespace kasumi::cli::i18n

#endif // KASUMI_CLI_I18N_HPP
