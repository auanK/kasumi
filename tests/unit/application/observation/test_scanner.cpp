#include "application/observation/patch.hpp"
#include "application/observation/scanner.hpp"
#include "application/observation/state.hpp"
#include "core/history.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/change_journal.hpp"
#include "platform/change_journal_diagnostic.hpp"
#include "platform/metadata.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>

namespace {

enum class FingerprintFakeMode {
    Supported,
    Unsupported,
    ErrorBefore,
    ErrorAfter,
};

FingerprintFakeMode fingerprint_fake_mode = FingerprintFakeMode::Unsupported;
int fingerprint_fake_calls = 0;

kasumi::platform::FileFingerprintResult
fake_fingerprint(const std::filesystem::path&) {
    ++fingerprint_fake_calls;
    if (fingerprint_fake_mode == FingerprintFakeMode::ErrorBefore)
        return std::unexpected("fingerprint before hash failed");
    if (fingerprint_fake_mode == FingerprintFakeMode::ErrorAfter &&
        fingerprint_fake_calls > 1)
        return std::unexpected("fingerprint after hash failed");
    if (fingerprint_fake_mode == FingerprintFakeMode::Unsupported)
        return std::optional<kasumi::platform::FileFingerprint>{};
    return std::optional<kasumi::platform::FileFingerprint>{
        kasumi::platform::FileFingerprint{
            .kind = kasumi::platform::FileFingerprintKind::WindowsFileIdentity,
            .value = {1, 2, 3, 4}}};
}

void set_fingerprint_fake(FingerprintFakeMode mode) {
    fingerprint_fake_mode = mode;
    fingerprint_fake_calls = 0;
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

TEST(ScannerTest, UnicodeFilenameRoundTrip) {
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-unicode-roundtrip");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    const std::string expected_dir_utf8 = "pasta-日本";
    const std::string expected_file_utf8 = "pasta-日本/usuário-☁.txt";

    const auto dir_path =
        root / std::filesystem::path(
                   reinterpret_cast<const char8_t*>(u8"pasta-日本"));
    std::filesystem::create_directories(dir_path);
    const auto file_path =
        dir_path / std::filesystem::path(
                       reinterpret_cast<const char8_t*>(u8"usuário-☁.txt"));
    kasumi::test::write_text(file_path, "conteúdo de teste unicode");

    const auto scan =
        kasumi::application::observation::scanner::scan_result(root);
    ASSERT_TRUE(scan.has_value());

    const auto* dir_row = kasumi::find_row(scan->snapshot, expected_dir_utf8);
    ASSERT_NE(dir_row, nullptr);
    EXPECT_EQ(dir_row->path, expected_dir_utf8);
    EXPECT_TRUE(dir_row->is_directory);

    const auto* file_row = kasumi::find_row(scan->snapshot, expected_file_utf8);
    ASSERT_NE(file_row, nullptr);
    EXPECT_EQ(file_row->path, expected_file_utf8);
    EXPECT_FALSE(file_row->is_directory);
    EXPECT_GT(file_row->size, 0U);

    // Commit round trip
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
    auto workspace =
        kasumi::test::make_temp_workspace("scanner-posix-unicode-case-collision");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    kasumi::test::write_text(root / "Ä.txt", "upper");
    kasumi::test::write_text(root / "ä.txt", "lower");

    const auto result =
        kasumi::application::observation::scanner::scan_result(root);
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(
        result.error().detail.find("case collision"),
        std::string::npos);
}
#endif

} // namespace
