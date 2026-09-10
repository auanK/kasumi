#include "application/observation/patch.hpp"
#include "application/observation/scanner.hpp"
#include "application/observation/state.hpp"
#include "core/history.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/hash_mutation.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/change_journal.hpp"
#include "platform/change_journal_diagnostic.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <gtest/gtest.h>
#include <iostream>
#include <thread>

namespace {

enum class FingerprintFakeMode {
    Supported,
    Unsupported,
    ErrorBefore,
    ErrorAfter,
    Changing,
    SettlesAfterFirst,
};

FingerprintFakeMode fingerprint_fake_mode = FingerprintFakeMode::Unsupported;
int fingerprint_fake_calls = 0;
int native_fingerprint_calls = 0;

kasumi::platform::FileFingerprintResult
fake_fingerprint(const std::filesystem::path&) {
    ++fingerprint_fake_calls;
    if (fingerprint_fake_mode == FingerprintFakeMode::ErrorBefore)
        return std::unexpected("fingerprint before hash failed");
    if (fingerprint_fake_mode == FingerprintFakeMode::ErrorAfter &&
        fingerprint_fake_calls > 1)
        return std::unexpected("fingerprint after hash failed");
    if (fingerprint_fake_mode == FingerprintFakeMode::Unsupported) {
        std::cout << "fingerprint_call=" << fingerprint_fake_calls
                  << " unavailable\n";
        return std::optional<kasumi::platform::FileFingerprint>{};
    }
    if (fingerprint_fake_mode == FingerprintFakeMode::Changing ||
        fingerprint_fake_mode == FingerprintFakeMode::SettlesAfterFirst) {
        const auto value = static_cast<std::uint64_t>(
            fingerprint_fake_mode == FingerprintFakeMode::Changing
                ? fingerprint_fake_calls
                : std::min(fingerprint_fake_calls, 2));
        std::cout << "fingerprint_call=" << fingerprint_fake_calls << " F"
                  << value << '\n';
        return std::optional<kasumi::platform::FileFingerprint>{
            kasumi::platform::FileFingerprint{
                .kind =
                    kasumi::platform::FileFingerprintKind::WindowsFileIdentity,
                .value = {1, 2, 3, value}}};
    }
    return std::optional<kasumi::platform::FileFingerprint>{
        kasumi::platform::FileFingerprint{
            .kind = kasumi::platform::FileFingerprintKind::WindowsFileIdentity,
            .value = {1, 2, 3, 4}}};
}

void set_fingerprint_fake(FingerprintFakeMode mode) {
    fingerprint_fake_mode = mode;
    fingerprint_fake_calls = 0;
}

kasumi::platform::FileFingerprintResult
traced_native_fingerprint(const std::filesystem::path& path) {
    ++native_fingerprint_calls;
    const auto result = kasumi::platform::regular_file_fingerprint(path);
    std::cout << "fingerprint_call=" << native_fingerprint_calls << ' ';
    if (!result)
        std::cout << "error=" << result.error();
    else if (!*result)
        std::cout << "unavailable";
    else {
        std::cout << static_cast<int>((**result).kind) << ':';
        for (const auto value : (**result).value)
            std::cout << value << ',';
    }
    std::cout << '\n';
    return result;
}

void expect_same_snapshot(const kasumi::Snapshot& left,
                          const kasumi::Snapshot& right) {
    ASSERT_EQ(left.rows.size(), right.rows.size());
    for (std::size_t index = 0; index < left.rows.size(); ++index) {
        EXPECT_EQ(left.rows[index].path, right.rows[index].path);
        EXPECT_EQ(left.rows[index].hash, right.rows[index].hash);
        EXPECT_EQ(left.rows[index].size, right.rows[index].size);
        EXPECT_EQ(left.rows[index].mtime, right.rows[index].mtime);
        EXPECT_EQ(left.rows[index].is_directory,
                  right.rows[index].is_directory);
    }
}

TEST(ScannerTest, IncrementalScanEqualsFullHashScan) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-equivalence");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / "z.txt", "zulu");
    kasumi::test::write_text(root / "a.txt", "alpha");
    kasumi::test::write_text(root / "nested" / "b.txt", "bravo");
    set_fingerprint_fake(FingerprintFakeMode::Supported);

    const auto full = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash,
        fake_fingerprint);
    ASSERT_TRUE(full.has_value());
    const auto incremental =
        kasumi::application::observation::scanner::scan_result(
            root,
            full->cache,
            kasumi::application::observation::scanner::ScanPolicy::
                ReuseStrongFingerprint,
            fake_fingerprint);
    ASSERT_TRUE(incremental.has_value());
    expect_same_snapshot(full->snapshot, incremental->snapshot);
    EXPECT_EQ(incremental->cache.size(), 3U);
    EXPECT_TRUE(
        std::ranges::is_sorted(incremental->cache,
                               kasumi::path_less,
                               &kasumi::state_storage::FileCacheRow::path));
}

TEST(ScannerTest, IgnoreRulesHandleGlobsAnchorsDirectoriesAndNegation) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-ignore-rules");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / ".kasumiignore",
                             "*.tmp\n"
                             "!important.tmp\n"
                             "/cache/\n"
                             "/root.txt\n"
                             "docs/**/secret?.txt\n");
    kasumi::test::write_text(root / "drop.tmp", "ignored");
    kasumi::test::write_text(root / "important.tmp", "kept");
    kasumi::test::write_text(root / "cache" / "cached.txt", "ignored");
    kasumi::test::write_text(root / "root.txt", "ignored");
    kasumi::test::write_text(root / "nested" / "root.txt", "kept");
    kasumi::test::write_text(root / "docs" / "v1" / "secret1.txt", "ignored");
    kasumi::test::write_text(root / "docs" / "v1" / "public.txt", "kept");

    const auto result = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(kasumi::find_row(result->snapshot, "drop.tmp"), nullptr);
    EXPECT_NE(kasumi::find_row(result->snapshot, "important.tmp"), nullptr);
    EXPECT_EQ(kasumi::find_row(result->snapshot, "cache"), nullptr);
    EXPECT_EQ(kasumi::find_row(result->snapshot, "root.txt"), nullptr);
    EXPECT_NE(kasumi::find_row(result->snapshot, "nested/root.txt"), nullptr);
    EXPECT_EQ(kasumi::find_row(result->snapshot, "docs/v1/secret1.txt"),
              nullptr);
    EXPECT_NE(kasumi::find_row(result->snapshot, "docs/v1/public.txt"),
              nullptr);

    EXPECT_FALSE(kasumi::application::observation::scanner::observe_file(
        root, "drop.tmp"));
    EXPECT_TRUE(kasumi::application::observation::scanner::observe_file(
        root, "important.tmp"));
}

TEST(ScannerTest, TargetedObservationAndPatchMatchFullHash) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-targeted-patch");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    const auto file = root / "a.txt";
    kasumi::test::write_text(file, "alpha");
    set_fingerprint_fake(FingerprintFakeMode::Supported);
    const auto first = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash,
        fake_fingerprint);
    ASSERT_TRUE(first.has_value());
    ASSERT_FALSE(first->cache.empty());
    kasumi::test::write_text(file, "omega");
    set_fingerprint_fake(FingerprintFakeMode::Unsupported);
    const auto targeted =
        kasumi::application::observation::scanner::observe_file(
            root, "a.txt", first->cache.front(), fake_fingerprint);
    ASSERT_TRUE(targeted.has_value());
    const auto patched = kasumi::application::observation::apply_local_delta(
        first->snapshot,
        std::array<kasumi::application::observation::ObservedFileDelta, 1>{
            kasumi::application::observation::ObservedFileDelta{
                .path = targeted->row.path, .row = targeted->row}});
    ASSERT_TRUE(patched.has_value());
    const auto full = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash);
    ASSERT_TRUE(full.has_value());
    expect_same_snapshot(*patched, full->snapshot);
}

TEST(ScannerTest, TargetedCreateNeedsFullScan) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-targeted-create");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / "a.txt", "alpha");
    const auto first = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash);
    ASSERT_TRUE(first.has_value());
    kasumi::test::write_text(root / "b.txt", "bravo");
    const auto targeted =
        kasumi::application::observation::scanner::observe_file(root, "b.txt");
    ASSERT_TRUE(targeted.has_value());
    const auto patched = kasumi::application::observation::apply_local_delta(
        first->snapshot,
        std::array<kasumi::application::observation::ObservedFileDelta, 1>{
            kasumi::application::observation::ObservedFileDelta{
                .path = targeted->row.path, .row = targeted->row}});
    EXPECT_FALSE(patched.has_value());
    const auto full = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash);
    ASSERT_TRUE(full.has_value());
    EXPECT_NE(kasumi::find_row(full->snapshot, "b.txt"), nullptr);
}

TEST(ScannerTest, TargetedObservationRejectsDirectory) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-targeted-directory");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    std::error_code error;
    std::filesystem::create_directories(root / "nested", error);
    ASSERT_FALSE(error);
    const auto targeted =
        kasumi::application::observation::scanner::observe_file(root, "nested");
    EXPECT_FALSE(targeted.has_value());
}

TEST(ScannerTest, SameSizeMutationInvalidatesCachedHash) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-mutation");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    const auto file = root / "a.txt";
    kasumi::test::write_text(file, "alpha");
    const auto first = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash);
    ASSERT_TRUE(first.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
    kasumi::test::write_text(file, "omega");
    const auto second = kasumi::application::observation::scanner::scan_result(
        root,
        first->cache,
        kasumi::application::observation::scanner::ScanPolicy::
            ReuseStrongFingerprint);
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(kasumi::find_row(first->snapshot, "a.txt")->hash,
              kasumi::find_row(second->snapshot, "a.txt")->hash);
}

TEST(ScannerTest, ReplaceAtSamePathInvalidatesCachedHash) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-replace");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    const auto file = root / "a.txt";
    kasumi::test::write_text(file, "alpha");
    const auto first = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash);
    ASSERT_TRUE(first.has_value());
    std::filesystem::remove(file);
    kasumi::test::write_text(file, "omega");
    const auto second = kasumi::application::observation::scanner::scan_result(
        root,
        first->cache,
        kasumi::application::observation::scanner::ScanPolicy::
            ReuseStrongFingerprint);
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(kasumi::find_row(first->snapshot, "a.txt")->hash,
              kasumi::find_row(second->snapshot, "a.txt")->hash);
}

TEST(ScannerTest, RestoredMtimeDoesNotHideContentMutation) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-restored-mtime");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    const auto file = root / "a.txt";
    kasumi::test::write_text(file, "alpha");
    const auto old_mtime = std::filesystem::last_write_time(file);
    const auto first = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash);
    ASSERT_TRUE(first.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
    kasumi::test::write_text(file, "omega");
    ASSERT_TRUE(
        kasumi::platform::metadata::set_last_write_time(file, old_mtime));
    const auto second = kasumi::application::observation::scanner::scan_result(
        root,
        first->cache,
        kasumi::application::observation::scanner::ScanPolicy::
            ReuseStrongFingerprint);
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(kasumi::find_row(first->snapshot, "a.txt")->hash,
              kasumi::find_row(second->snapshot, "a.txt")->hash);
}

TEST(ScannerTest, FingerprintUnavailableFallsBackToFullHash) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-unsupported");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / "a.txt", "alpha");
    set_fingerprint_fake(FingerprintFakeMode::Unsupported);

    const auto result = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash,
        fake_fingerprint);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->snapshot.rows.size(), 2U);
    EXPECT_FALSE(result->snapshot.rows[1].hash.empty());
    EXPECT_TRUE(result->cache.empty());
}

TEST(ScannerTest, UnsupportedFingerprintDoesNotCreateCacheEntry) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-no-cache");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / "a.txt", "alpha");
    set_fingerprint_fake(FingerprintFakeMode::Unsupported);

    const auto result = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash,
        fake_fingerprint);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->cache.empty());
}

TEST(ScannerTest, FingerprintErrorBeforeHashFailsClosed) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-error-before");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / "a.txt", "alpha");
    set_fingerprint_fake(FingerprintFakeMode::ErrorBefore);

    const auto result = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash,
        fake_fingerprint);

    EXPECT_FALSE(result.has_value());
}

TEST(ScannerTest, FingerprintErrorAfterHashFailsClosed) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-error-after");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / "a.txt", "alpha");
    set_fingerprint_fake(FingerprintFakeMode::ErrorAfter);

    const auto result = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash,
        fake_fingerprint);

    EXPECT_FALSE(result.has_value());
}

TEST(ScannerTest, FingerprintUnavailableNeverReusesPreviousHash) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-no-reuse");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    const auto file = root / "a.txt";
    kasumi::test::write_text(file, "alpha");
    set_fingerprint_fake(FingerprintFakeMode::Supported);
    const auto first = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash,
        fake_fingerprint);
    ASSERT_TRUE(first.has_value());
    ASSERT_EQ(first->cache.size(), 1U);
    ASSERT_EQ(first->cache.front().path, "a.txt");
    const auto old_hash = kasumi::find_row(first->snapshot, "a.txt")->hash;
    ASSERT_EQ(first->cache.front().hash, old_hash);

    kasumi::test::write_text(file, "omega");
    set_fingerprint_fake(FingerprintFakeMode::Unsupported);
    const auto second = kasumi::application::observation::scanner::scan_result(
        root,
        first->cache,
        kasumi::application::observation::scanner::ScanPolicy::
            ReuseStrongFingerprint,
        fake_fingerprint);

    ASSERT_TRUE(second.has_value());
    const auto new_hash = kasumi::find_row(second->snapshot, "a.txt")->hash;
    EXPECT_NE(old_hash, new_hash);
    EXPECT_FALSE(new_hash.empty());
    EXPECT_TRUE(second->cache.empty());
}

TEST(ScannerTest,
     PersistedCheckpointNoOpCannotFallBackBecauseOfWorkerScheduling) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-usn-clean");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    const auto checkpoint =
        kasumi::platform::capture_change_journal_checkpoint(root);
    if (!checkpoint) {
        GTEST_SKIP() << checkpoint.error();
    }
    kasumi::test::write_text(root / "a.txt", "alpha");
    kasumi::application::observation::LocalObservationSession session;
    const auto scanned =
        kasumi::application::observation::collect_local_tree(root, &session);
    ASSERT_TRUE(scanned.has_value());
    const auto scanner_invocations = session.scanner_invocations;
    session.cache_dirty = false;

    const auto result =
        kasumi::application::observation::collect_local_tree(root, &session);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(session.scanner_invocations, scanner_invocations);
    EXPECT_FALSE(session.cache_dirty);
    expect_same_snapshot(*result, *scanned);
}

TEST(ScannerTest, DirtyUsnFallsBackOnceAndMarksCacheDirty) {
    auto workspace = kasumi::test::make_temp_workspace("scanner-usn-dirty");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    const auto file = root / "a.txt";
    kasumi::test::write_text(file, "alpha");
    auto scanned = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash);
    ASSERT_TRUE(scanned.has_value());
    auto checkpoint = kasumi::platform::capture_change_journal_checkpoint(root);
    if (!checkpoint) {
        GTEST_SKIP() << checkpoint.error();
    }
    kasumi::application::observation::LocalObservationSession session;
    session.cache = scanned->cache;
    session.cache_loaded = true;
    session.checkpoint = kasumi::state_storage::ObservationCheckpoint{
        .journal = *checkpoint,
        .tree_root_hash = scanned->snapshot.rows.front().hash,
        .row_count = scanned->snapshot.rows.size(),
        .directory_file_references = {},
        .lineage_complete = false};
    session.last_snapshot = scanned->snapshot;
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
    kasumi::test::write_text(file, "omega");

    const auto result =
        kasumi::application::observation::collect_local_tree(root, &session);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(session.scanner_invocations, 1U);
    EXPECT_TRUE(session.cache_dirty);
    ASSERT_EQ(result->rows.size(), scanned->snapshot.rows.size());
    EXPECT_NE(result->rows.front().hash, scanned->snapshot.rows.front().hash);
}

TEST(ScannerTest, ResolutionSeamKeepsLiveInsideObjectsDirty) {
    const kasumi::platform::SyntheticResolutionEvidence evidence{
        .file_path_resolved = true, .file_inside_root = true};
    EXPECT_EQ(kasumi::platform::classify_resolution_evidence(evidence),
              kasumi::platform::ChangeEvidence::Dirty);
}

TEST(ScannerTest, ResolutionSeamAllowsOnlyProvenDeletedOutsideObjectsClean) {
    const kasumi::platform::SyntheticResolutionEvidence evidence{
        .parent_path_resolved = true,
        .parent_inside_root = false,
        .file_missing = true,
        .filename_valid = true};
    EXPECT_EQ(kasumi::platform::classify_resolution_evidence(evidence),
              kasumi::platform::ChangeEvidence::Clean);
}

TEST(ScannerTest, ResolutionSeamKeepsMissingParentIndeterminate) {
    const kasumi::platform::SyntheticResolutionEvidence evidence{
        .file_missing = true, .parent_missing = true, .filename_valid = true};
    EXPECT_EQ(kasumi::platform::classify_resolution_evidence(evidence),
              kasumi::platform::ChangeEvidence::Indeterminate);
}

TEST(ScannerTest, ResolutionSeamNeverTurnsAmbiguousRenameClean) {
    const kasumi::platform::SyntheticResolutionEvidence evidence{
        .parent_path_resolved = true,
        .parent_inside_root = false,
        .file_missing = true,
        .filename_valid = true,
        .parent_history_ambiguous = true};
    EXPECT_EQ(kasumi::platform::classify_resolution_evidence(evidence),
              kasumi::platform::ChangeEvidence::Indeterminate);
}

TEST(ScannerTest, ResolutionSeamKeepsAccessDeniedIndeterminate) {
    const kasumi::platform::SyntheticResolutionEvidence evidence{
        .parent_path_resolved = true,
        .parent_inside_root = false,
        .file_missing = true,
        .filename_valid = true,
        .access_denied = true};
    EXPECT_EQ(kasumi::platform::classify_resolution_evidence(evidence),
              kasumi::platform::ChangeEvidence::Indeterminate);
}

kasumi::platform::DirectoryLineageView
complete_lineage(const std::vector<std::uint64_t>& references) {
    return {.inside_directory_frns = references,
            .complete = true,
            .checkpoint_bound = true};
}

TEST(ScannerTest, CompleteLineageClassifiesOutsideTransientAsClean) {
    const std::vector<std::uint64_t> directories{10, 20, 30};
    EXPECT_EQ(kasumi::platform::classify_record_membership(
                  {.file_reference = 99, .parent_reference = 98},
                  complete_lineage(directories)),
              kasumi::platform::ChangeEvidence::Clean);
}

TEST(ScannerTest, CompleteLineageClassifiesInsideTransientAsDirty) {
    const std::vector<std::uint64_t> directories{10, 20, 30};
    EXPECT_EQ(kasumi::platform::classify_record_membership(
                  {.file_reference = 99, .parent_reference = 20},
                  complete_lineage(directories)),
              kasumi::platform::ChangeEvidence::Dirty);
}

TEST(ScannerTest, IncompleteLineageIsIndeterminate) {
    const std::vector<std::uint64_t> directories{10};
    EXPECT_EQ(kasumi::platform::classify_record_membership(
                  {.file_reference = 99, .parent_reference = 98},
                  {.inside_directory_frns = directories,
                   .complete = false,
                   .checkpoint_bound = true}),
              kasumi::platform::ChangeEvidence::Indeterminate);
}

TEST(ScannerTest, KnownInsideDirectoryFileFrnIsDirty) {
    const std::vector<std::uint64_t> directories{10, 20};
    EXPECT_EQ(kasumi::platform::classify_record_membership(
                  {.file_reference = 20, .parent_reference = 99},
                  complete_lineage(directories)),
              kasumi::platform::ChangeEvidence::Dirty);
}

TEST(ScannerTest, KnownInsideParentFrnIsDirty) {
    const std::vector<std::uint64_t> directories{10, 20};
    EXPECT_EQ(kasumi::platform::classify_record_membership(
                  {.file_reference = 99, .parent_reference = 20},
                  complete_lineage(directories)),
              kasumi::platform::ChangeEvidence::Dirty);
}

TEST(ScannerTest, OutsideToInsideRenameIsDirty) {
    const std::vector<std::uint64_t> directories{10, 20};
    EXPECT_EQ(kasumi::platform::classify_record_membership(
                  {.file_reference = 99,
                   .parent_reference = 20,
                   .is_directory = true},
                  complete_lineage(directories)),
              kasumi::platform::ChangeEvidence::Dirty);
}

TEST(ScannerTest, InsideToOutsideRenameIsDirty) {
    const std::vector<std::uint64_t> directories{10, 20};
    EXPECT_EQ(kasumi::platform::classify_record_membership(
                  {.file_reference = 20,
                   .parent_reference = 99,
                   .is_directory = true},
                  complete_lineage(directories)),
              kasumi::platform::ChangeEvidence::Dirty);
}

TEST(ScannerTest, DeletedKnownInsideDirectoryIsDirty) {
    const std::vector<std::uint64_t> directories{10, 20};
    EXPECT_EQ(kasumi::platform::classify_record_membership(
                  {.file_reference = 20,
                   .parent_reference = 10,
                   .is_directory = true},
                  complete_lineage(directories)),
              kasumi::platform::ChangeEvidence::Dirty);
}

TEST(ScannerTest, JournalGapWithLineageIsIndeterminate) {
    const std::vector<std::uint64_t> directories{10, 20};
    EXPECT_EQ(kasumi::platform::classify_record_membership(
                  {.file_reference = 99, .parent_reference = 98},
                  {.inside_directory_frns = directories,
                   .complete = true,
                   .checkpoint_bound = false}),
              kasumi::platform::ChangeEvidence::Indeterminate);
}

TEST(ScannerTest, LineageCheckpointMismatchFallsBack) {
    const std::vector<std::uint64_t> directories{10, 20};
    EXPECT_EQ(kasumi::platform::classify_record_membership(
                  {.file_reference = 99, .parent_reference = 98},
                  {.inside_directory_frns = directories,
                   .complete = true,
                   .checkpoint_bound = false}),
              kasumi::platform::ChangeEvidence::Indeterminate);
}

TEST(ScannerTest, UnicodeSupplementaryPathsAndTargetedObservation) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-unicode-supplementary");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    constexpr std::array<std::string_view, 4> paths{
        "高松灯/カード💝.png",
        "Icons/Karyl💝.png",
        "Icons/𝑬𝒎𝒊𝒍𝒊𝒂.txt",
        "Icons/𓆩🌸𓆪.txt",
    };
    for (const auto path : paths) {
        kasumi::test::write_text(root / kasumi::platform::path::from_utf8(path),
                                 "original");
    }
    set_fingerprint_fake(FingerprintFakeMode::Supported);
    const auto scan = kasumi::application::observation::scanner::scan_result(
        root,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash,
        fake_fingerprint);
    ASSERT_TRUE(scan.has_value())
        << kasumi::application::observation::scanner::describe(scan.error());
    ASSERT_EQ(scan->snapshot.rows.size(), 7U);
    ASSERT_EQ(scan->cache.size(), paths.size());
    for (const auto path : paths) {
        SCOPED_TRACE(path);
        const auto* row = kasumi::find_row(scan->snapshot, path);
        ASSERT_NE(row, nullptr);
        EXPECT_EQ(row->path, path);
        EXPECT_FALSE(row->is_directory);
        const auto cached = std::ranges::find(
            scan->cache, path, &kasumi::state_storage::FileCacheRow::path);
        ASSERT_NE(cached, scan->cache.end());
        EXPECT_EQ(cached->path, path);

        const auto file = root / kasumi::platform::path::from_utf8(path);
        kasumi::test::write_text(file, "updated Unicode content");
        const auto targeted =
            kasumi::application::observation::scanner::observe_file(
                root, path, *cached, fake_fingerprint);
        ASSERT_TRUE(targeted.has_value())
            << kasumi::application::observation::scanner::describe(
                   targeted.error());
        EXPECT_EQ(targeted->row.path, path);
        EXPECT_NE(targeted->row.hash, row->hash);
        ASSERT_TRUE(targeted->cache.has_value());
        EXPECT_EQ(targeted->cache->path, path);
        EXPECT_EQ(targeted->cache->hash, targeted->row.hash);
    }
}

TEST(ScannerTest, FullHashRejectsTwoUnstableAttempts) {
    auto workspace = kasumi::test::make_temp_workspace("unstable-full");
    const auto file = kasumi::test::workspace_path(workspace, "a.txt");
    kasumi::test::write_text(file, "alpha");
    set_fingerprint_fake(FingerprintFakeMode::Changing);
    using namespace kasumi::application::observation::scanner;
    const auto result =
        scan_result(file, {}, ScanPolicy::FullHash, fake_fingerprint);
    EXPECT_FALSE(result) << "FullHash accepted an unstable observation";
    EXPECT_EQ(fingerprint_fake_calls, 3);
    if (result) {
        std::cout << "unexpected_row_hash="
                  << kasumi::hash_hex(result->snapshot.rows.front().hash)
                  << '\n';
    }
    kasumi::test::print_file_evidence("FullHash F1/F2/F3 rejected", file);
}

TEST(ScannerTest, ReuseRejectsTwoUnstableAttempts) {
    auto workspace = kasumi::test::make_temp_workspace("unstable-reuse");
    const auto file = kasumi::test::workspace_path(workspace, "a.txt");
    kasumi::test::write_text(file, "alpha");
    set_fingerprint_fake(FingerprintFakeMode::Changing);
    using namespace kasumi::application::observation::scanner;
    const auto result = scan_result(
        file, {}, ScanPolicy::ReuseStrongFingerprint, fake_fingerprint);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().detail, "file changed while being read");
    EXPECT_EQ(fingerprint_fake_calls, 3);
    kasumi::test::print_file_evidence("Reuse F1/F2/F3 rejected", file);
}

TEST(ScannerTest, RetryUsesFreshBaselineAfterDetectedChange) {
    auto workspace = kasumi::test::make_temp_workspace("stale-baseline");
    const auto file = kasumi::test::workspace_path(workspace, "a.txt");
    kasumi::test::write_text(file, "alpha");
    set_fingerprint_fake(FingerprintFakeMode::SettlesAfterFirst);
    using namespace kasumi::application::observation::scanner;
    const auto result = scan_result(
        file, {}, ScanPolicy::ReuseStrongFingerprint, fake_fingerprint);
    EXPECT_TRUE(result) << "retry kept F1 instead of adopting F2: "
                        << result.error().detail;
    EXPECT_EQ(fingerprint_fake_calls, 3);
    kasumi::test::print_file_evidence(
        "Reuse F1/F2/F2 accepted with fresh baseline", file);
}

TEST(ScannerTest, UnavailableFingerprintRejectsSameSizeOverwrite) {
    using namespace kasumi::application::observation::scanner;
    using namespace kasumi::test;
    for (auto policy :
         {ScanPolicy::FullHash, ScanPolicy::ReuseStrongFingerprint}) {
        SCOPED_TRACE(policy == ScanPolicy::FullHash ? "FullHash"
                                                    : "ReuseStrongFingerprint");
        auto workspace = make_temp_workspace("no-fingerprint-mutation");
        const auto file = workspace_path(workspace, "large.bin");
        write_large_file(file);
        const auto initial_hash = independent_file_hash(file);
        const auto initial_size = std::filesystem::file_size(file);
        const auto initial_time = std::filesystem::last_write_time(file);
        std::cout << "policy="
                  << (policy == ScanPolicy::FullHash ? "FullHash"
                                                     : "ReuseStrongFingerprint")
                  << " mutation=same-size-overwrite\n";
        print_file_evidence("initial", file);
        set_fingerprint_fake(FingerprintFakeMode::Unsupported);
        HashMutation mutation(file, [&] {
            mutate_large_file(file, FileMutation::Overwrite);
        });
        const auto result = scan_result(file, {}, policy, fake_fingerprint);
        const auto final_hash = independent_file_hash(file);
        print_file_evidence("final", file);
        ASSERT_EQ(mutation.mutations, 1U);
        ASSERT_EQ(mutation.hashes.size(), 1U);
        std::cout << "hash_attempts=" << mutation.hashes.size()
                  << " attempt_hash=" << kasumi::hash_hex(mutation.hashes[0])
                  << '\n';
        EXPECT_NE(initial_hash, final_hash);
        EXPECT_NE(mutation.hashes[0], initial_hash);
        EXPECT_NE(mutation.hashes[0], final_hash);
        EXPECT_EQ(fingerprint_fake_calls, 2);
        if (result) {
            const auto& row = result->snapshot.rows.front();
            EXPECT_TRUE(result->cache.empty());
            EXPECT_EQ(row.size, initial_size);
            EXPECT_EQ(row.mtime, initial_time);
            EXPECT_EQ(row.hash, mutation.hashes[0]);
            std::cout << "scanner=success row_size=" << row.size
                      << " row_mtime=" << row.mtime.time_since_epoch().count()
                      << " row_hash=" << kasumi::hash_hex(row.hash) << '\n';
        }
        EXPECT_FALSE(result)
            << "fingerprint unavailable was treated as proof of stability";
    }
}

TEST(ScannerTest, RealMutationsDuringHashNeverReturnHybridRows) {
    using namespace kasumi::application::observation::scanner;
    using namespace kasumi::test;
    for (auto policy :
         {ScanPolicy::FullHash, ScanPolicy::ReuseStrongFingerprint}) {
        for (auto mode : {FileMutation::Append,
                          FileMutation::Truncate,
                          FileMutation::Overwrite}) {
            SCOPED_TRACE(testing::Message()
                         << "policy=" << static_cast<int>(policy)
                         << " mutation=" << static_cast<int>(mode));
            auto workspace = make_temp_workspace("real-hash-mutation");
            const auto file = workspace_path(workspace, "large.bin");
            write_large_file(file);
            const auto initial_hash = independent_file_hash(file);
            const auto initial_size = std::filesystem::file_size(file);
            const auto initial_time = std::filesystem::last_write_time(file);
            const auto native =
                kasumi::platform::regular_file_fingerprint(file);
            ASSERT_TRUE(native);
            const auto* policy_name = policy == ScanPolicy::FullHash
                                          ? "FullHash"
                                          : "ReuseStrongFingerprint";
            const auto* mutation_name = mode == FileMutation::Append ? "append"
                                        : mode == FileMutation::Truncate
                                            ? "truncate"
                                            : "same-size-overwrite";
            std::cout << "policy=" << policy_name
                      << " mutation=" << mutation_name << '\n';
            print_file_evidence("before", file);
            HashMutation mutation(file, [&] {
                mutate_large_file(file, mode);
            });
            native_fingerprint_calls = 0;
            kasumi::platform::perf_trace::force_enable(true);
            kasumi::platform::perf_trace::reset();
            const auto result =
                scan_result(file, {}, policy, traced_native_fingerprint);
            const auto changed = kasumi::platform::perf_trace::get_count(
                "files changed during hash");
            kasumi::platform::perf_trace::force_enable(false);
            ASSERT_EQ(mutation.mutations, 1U);
            ASSERT_FALSE(mutation.hashes.empty());
            const auto final_hash = independent_file_hash(file);
            print_file_evidence("after", file);
            for (const auto& hash : mutation.hashes)
                std::cout << "attempt_hash=" << kasumi::hash_hex(hash) << '\n';
            std::cout << "hash_attempts=" << mutation.hashes.size()
                      << " instability_detections=" << changed << '\n';
            EXPECT_NE(initial_hash, final_hash);
            if (mode == FileMutation::Overwrite) {
                EXPECT_NE(mutation.hashes.front(), initial_hash);
                EXPECT_NE(mutation.hashes.front(), final_hash);
                EXPECT_EQ(mutation.hashes.front(),
                          kasumi::hasher::hash_string(
                              std::string(mutation_mib, 'A') +
                              std::string(31 * mutation_mib, 'B')));
            }
            if (!*native) {
                ASSERT_FALSE(result);
                EXPECT_EQ(result.error().detail,
                          "file changed while being read");
                std::cout << "scanner=error returned_hash=N/A "
                          << result.error().detail << '\n';
            } else {
                ASSERT_TRUE(result) << describe(result.error());
                const auto& row = result->snapshot.rows.front();
                EXPECT_EQ(row.size, std::filesystem::file_size(file));
                EXPECT_EQ(row.mtime, std::filesystem::last_write_time(file));
                EXPECT_NE(row.mtime, initial_time);
                EXPECT_EQ(row.hash, mutation.hashes.back());
                EXPECT_EQ(row.hash, final_hash);
                if (mode != FileMutation::Overwrite) {
                    EXPECT_NE(row.size, initial_size);
                }
                std::cout << "scanner=success row_size=" << row.size
                          << " row_mtime="
                          << row.mtime.time_since_epoch().count()
                          << " row_hash=" << kasumi::hash_hex(row.hash) << '\n';
            }
            EXPECT_EQ(changed, 1U);
            EXPECT_EQ(mutation.hashes.size(), *native ? 2U : 1U);
            EXPECT_EQ(native_fingerprint_calls, *native ? 3 : 2);
        }
    }
}

TEST(ScannerTest, UnicodeSingleFileAndErrorDisplay) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-unicode-single-file");
    const auto file = kasumi::test::workspace_path(workspace, "local") /
                      kasumi::platform::path::from_utf8("千早愛音🌸.txt");
    kasumi::test::write_text(file, "content");
    const auto scanned =
        kasumi::application::observation::scanner::scan_result(file);
    ASSERT_TRUE(scanned.has_value())
        << kasumi::application::observation::scanner::describe(scanned.error());
    ASSERT_EQ(scanned->snapshot.rows.size(), 1U);
    EXPECT_EQ(scanned->snapshot.rows.front().path, "千早愛音🌸.txt");

    const auto missing =
        kasumi::application::observation::scanner::observe_file(
            file.parent_path(), "missing-𓆩🌸𓆪.txt");
    ASSERT_FALSE(missing.has_value());
    EXPECT_NE(
        kasumi::application::observation::scanner::describe(missing.error())
            .find("missing-𓆩🌸𓆪.txt"),
        std::string::npos);
}

TEST(ScannerTest, UnicodeIgnoreRulesExcludeAndReincludeFiles) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-unicode-ignore");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / ".kasumiignore",
                             "/千早愛音/\n"
                             "高松灯/*.png\n"
                             "!高松灯/カード💝.png\n"
                             "𓆩🌸𓆪.txt\n");
    constexpr std::array<std::string_view, 3> excluded{
        "千早愛音/Karyl💝.png", "高松灯/除外🌸.png", "Icons/𓆩🌸𓆪.txt"};
    constexpr std::array<std::string_view, 2> included{"高松灯/カード💝.png",
                                                       "Icons/𝑬𝒎𝒊𝒍𝒊𝒂.txt"};
    for (const auto path : excluded) {
        kasumi::test::write_text(root / kasumi::platform::path::from_utf8(path),
                                 "ignored");
    }
    for (const auto path : included) {
        kasumi::test::write_text(root / kasumi::platform::path::from_utf8(path),
                                 "kept");
    }
    const auto scanned =
        kasumi::application::observation::scanner::scan_result(root);
    ASSERT_TRUE(scanned.has_value())
        << kasumi::application::observation::scanner::describe(scanned.error());
    EXPECT_EQ(kasumi::find_row(scanned->snapshot, "千早愛音"), nullptr);
    for (const auto path : excluded) {
        SCOPED_TRACE(path);
        EXPECT_EQ(kasumi::find_row(scanned->snapshot, path), nullptr);
        EXPECT_FALSE(kasumi::application::observation::scanner::observe_file(
            root, path));
    }
    for (const auto path : included) {
        SCOPED_TRACE(path);
        EXPECT_NE(kasumi::find_row(scanned->snapshot, path), nullptr);
        const auto observed =
            kasumi::application::observation::scanner::observe_file(root, path);
        ASSERT_TRUE(observed.has_value())
            << kasumi::application::observation::scanner::describe(
                   observed.error());
        EXPECT_EQ(observed->row.path, path);
    }
}

TEST(ScannerTest, UnicodeFilenameRoundTrip) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-unicode-roundtrip");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    const std::string expected_dir_utf8 = "pasta-日本";
    const std::string expected_file_utf8 = "pasta-日本/usuário-☁.txt";

    const auto dir_path =
        root / kasumi::platform::path::from_utf8(expected_dir_utf8);
    std::filesystem::create_directories(dir_path);
    const auto file_path =
        root / kasumi::platform::path::from_utf8(expected_file_utf8);
    kasumi::test::write_text(file_path, "conteúdo de teste unicode");

    const auto scan =
        kasumi::application::observation::scanner::scan_result(root);
    ASSERT_TRUE(scan.has_value())
        << kasumi::application::observation::scanner::describe(scan.error());

    const auto* dir_row = kasumi::find_row(scan->snapshot, expected_dir_utf8);
    ASSERT_NE(dir_row, nullptr);
    EXPECT_EQ(dir_row->path, expected_dir_utf8);
    EXPECT_TRUE(dir_row->is_directory);

    const auto* file_row = kasumi::find_row(scan->snapshot, expected_file_utf8);
    ASSERT_NE(file_row, nullptr);
    EXPECT_EQ(file_row->path, expected_file_utf8);
    EXPECT_FALSE(file_row->is_directory);
    EXPECT_GT(file_row->size, 0U);

    const auto commit = kasumi::history::make_bootstrap(scan->snapshot, 0);
    ASSERT_TRUE(commit.has_value());
    const auto bytes = kasumi::history::serialize(*commit);
    ASSERT_TRUE(bytes.has_value());
    const auto deserialized = kasumi::history::deserialize(*bytes);
    ASSERT_TRUE(deserialized.has_value());

    const auto* roundtrip_dir =
        kasumi::find_row(deserialized->tree, expected_dir_utf8);
    ASSERT_NE(roundtrip_dir, nullptr);
    EXPECT_EQ(roundtrip_dir->path, expected_dir_utf8);
    EXPECT_TRUE(roundtrip_dir->is_directory);

    const auto* roundtrip_file =
        kasumi::find_row(deserialized->tree, expected_file_utf8);
    ASSERT_NE(roundtrip_file, nullptr);
    EXPECT_EQ(roundtrip_file->path, expected_file_utf8);
    EXPECT_EQ(roundtrip_file->hash, file_row->hash);
    EXPECT_EQ(roundtrip_file->size, file_row->size);
}

TEST(ScannerTest, ObserveFileRejectsNonPortablePathComponents) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-observe-non-portable");
    const auto root = kasumi::test::workspace_path(workspace, "local");

    auto res1 =
        kasumi::application::observation::scanner::observe_file(root, "CON");
    ASSERT_FALSE(res1.has_value());
    EXPECT_NE(
        res1.error().detail.find("unsupported non-portable path component"),
        std::string::npos);

    auto res2 =
        kasumi::application::observation::scanner::observe_file(root, "a:b");
    ASSERT_FALSE(res2.has_value());
    EXPECT_NE(
        res2.error().detail.find("unsupported non-portable path component"),
        std::string::npos);

    auto res3 = kasumi::application::observation::scanner::observe_file(
        root, "dir/file.");
    ASSERT_FALSE(res3.has_value());
    EXPECT_NE(
        res3.error().detail.find("unsupported non-portable path component"),
        std::string::npos);
}

#if !defined(_WIN32)
TEST(ScannerTest, ScanResultRejectsNonPortableEntriesOnPosix) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-posix-non-portable");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / "CON", "reserved device name on windows");

    const auto result =
        kasumi::application::observation::scanner::scan_result(root);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::observation::scanner::ScanErrorCode::Io);
    EXPECT_NE(
        result.error().detail.find("unsupported non-portable path component"),
        std::string::npos);
}

TEST(ScannerTest, ScanResultRejectsUnicodeCaseCollisionsOnPosix) {
    auto workspace = kasumi::test::make_temp_workspace(
        "scanner-posix-unicode-case-collision");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / "Ä.txt", "upper");
    kasumi::test::write_text(root / "ä.txt", "lower");

    const auto result =
        kasumi::application::observation::scanner::scan_result(root);
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().detail.find("case collision"), std::string::npos);
}
#endif

} // namespace
