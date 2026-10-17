#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "kasumi/test/history_storage.hpp"
#include "platform/cancellation.hpp"

#include <algorithm>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace {

namespace integrity = kasumi::application::integrity;
namespace history = kasumi::application::history_storage;
namespace protocol = history::maintenance_protocol;
namespace cancellation = kasumi::platform::cancellation;
using Failure = integrity::GcContentRemovalErrorCode;

class GcContentRemovalTest : public ::testing::Test {
protected:
    TempWorkspace workspace = kasumi::test::make_temp_workspace("gc-content-removal");
    FakeState* state = nullptr;
    kasumi::transport::Transport storage = make_fake_transport(state);
    history::RemoteLayout layout = history::derive_remote_layout(test_key());
    Commit commit = make_commit(0, {}, "file", "live").value();
    HeadReference head;
    std::string live = content("live");
    std::function<void()> between_observations;
    std::function<void(std::string_view)> before_content_remove;
    std::vector<std::string> removed_identifiers;
    std::vector<std::vector<std::uint8_t>> barrier_puts;

    static std::string content(std::string_view bytes) {
        return kasumi::crypto::content_identifier(
            test_key(), kasumi::hasher::hash_string(bytes));
    }

    HeadReference add_commit(const Commit& value, bool marker = true) {
        const auto canonical = kasumi::history::serialize(value).value();
        const auto plain = kasumi::test::workspace_path(workspace, "commit.plain");
        const auto encrypted = kasumi::test::workspace_path(workspace, "commit.enc");
        kasumi::test::write_binary(plain, std::as_bytes(std::span{canonical}));
        EXPECT_TRUE(kasumi::crypto::encrypt_file(
            plain, encrypted, test_key(), kasumi::crypto::FilePurpose::History));
        const HeadReference reference{
            commit_id(value), kasumi::hash_hex(
                kasumi::crypto::content::hash_file(encrypted).value())};
        EXPECT_TRUE(fake_put(state, encrypted, object_path(reference)));
        if (marker) state->objects[marker_path(reference)] = history::encode_marker(reference).value();
        return reference;
    }

    std::string add_orphan(std::string_view name) {
        const auto id = content(name);
        state->objects[id] = {'o', 'r', 'p', 'h', 'a', 'n'};
        return id;
    }

    void SetUp() override {
        cancellation::reset();
        head = add_commit(commit);
        state->objects[live] = {'c'};
        reset_fake_traffic(*state);

        storage.storage.put = [](void* context, const std::filesystem::path& path, std::string_view id) {
            auto* current = fake_state(context);
            EXPECT_EQ(id, history::derive_remote_layout(test_key()).barrier_identifier);
            if (current->on_operation) current->on_operation(*current, "before_put", id);
            auto result = fake_put(context, path, id);
            if (current->on_operation) current->on_operation(*current, "after_put", id);
            return result;
        };
        storage.storage.get = [](void* context, std::string_view id, const std::filesystem::path& path) {
            auto* current = fake_state(context);
            if (current->on_operation) current->on_operation(*current, "before_get", id);
            return fake_get(context, id, path);
        };
        storage.storage.remove = fake_remove;
        storage.storage.list = [](void* context) {
            auto* current = fake_state(context);
            if (current->on_operation) current->on_operation(*current, "before_list", {});
            return fake_list(context);
        };
        storage.storage.presence = [](void* context, std::string_view id) {
            return fake_presence(context, id);
        };
        storage.storage.put_batch = fake_put_batch;
        storage.storage.copy_batch = fake_copy_batch;
        storage.storage.remove_batch = fake_remove_batch;

        state->on_operation = [this](FakeState& current, std::string_view operation, std::string_view id) {
            if (operation == "after_put" && id == layout.barrier_identifier) {
                barrier_puts.push_back(current.objects[layout.barrier_identifier]);
            }
            if (operation == "before_list" && current.full_list_count == 1 && between_observations)
                between_observations();
            if (operation == "before_remove" && id != layout.barrier_identifier) {
                EXPECT_TRUE(current.objects.contains(layout.barrier_identifier));
                removed_identifiers.push_back(std::string(id));
                if (before_content_remove) before_content_remove(id);
            }
        };
    }

    void TearDown() override {
        cancellation::reset();
        // Strict invariant: GC content removal NEVER touches commits, markers, or quarantine
        EXPECT_EQ(state->commit_put_count, 0U);
        EXPECT_EQ(state->marker_put_count, 0U);
        EXPECT_EQ(state->copy_count, 0U);
        EXPECT_EQ(state->copy_batch_count, 0U);
        EXPECT_EQ(state->remove_batch_count, 0U);
        EXPECT_EQ(state->put_batch_count, 0U);
        EXPECT_EQ(state->put_files_batch_count, 0U);
        EXPECT_EQ(state->quarantine_payload_put_count, 0U);
        EXPECT_EQ(state->quarantine_metadata_put_count, 0U);
    }

    auto run_removal() {
        return integrity::remove_orphan_content_under_barrier(
            storage, test_key(), kasumi::test::workspace_root(workspace));
    }
};

// ============================================================================
// Grupo A — Fluxo nominal
// ============================================================================

TEST_F(GcContentRemovalTest, A1_NoOrphansProducesZeroRemovals) {
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->content_candidates, 0U);
    EXPECT_EQ(res->removed_content, 0U);
    EXPECT_EQ(res->already_absent, 0U);
    EXPECT_EQ(res->pending_commit_variants, 0U);
    EXPECT_TRUE(state->objects.contains(live));
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcContentRemovalTest, A2_SingleOrphanRemoved) {
    const auto o1 = add_orphan("orph1");
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->content_candidates, 1U);
    EXPECT_EQ(res->removed_content, 1U);
    EXPECT_EQ(res->already_absent, 0U);
    EXPECT_FALSE(state->objects.contains(o1));
    EXPECT_TRUE(state->objects.contains(live));
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcContentRemovalTest, A3_TenOrphansRemoved) {
    std::vector<std::string> orphans;
    for (int i = 0; i < 10; ++i) {
        orphans.push_back(add_orphan("orph_" + std::to_string(i)));
    }
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->content_candidates, 10U);
    EXPECT_EQ(res->removed_content, 10U);
    EXPECT_EQ(res->already_absent, 0U);
    for (const auto& id : orphans) {
        EXPECT_FALSE(state->objects.contains(id));
    }
    EXPECT_TRUE(state->objects.contains(live));
}

TEST_F(GcContentRemovalTest, A4_ProtectedContentRemainsIntact) {
    const auto o1 = add_orphan("orph1");
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(state->objects.contains(live));
    EXPECT_FALSE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, A5_RetainedHistoryContentRemainsIntact) {
    const auto base_commit = make_commit(0, {}, "base_file", "base_live").value();
    const auto base_head = add_commit(base_commit, false);
    const auto base_content = content("base_live");
    state->objects[base_content] = {'b'};

    const auto child_commit = make_commit(1, {commit_id(base_commit)}, "child_file", "child_live").value();
    add_commit(child_commit, true);
    const auto child_content = content("child_live");
    state->objects[child_content] = {'c'};

    const auto o1 = add_orphan("orph_a5");
    reset_fake_traffic(*state);
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(state->objects.contains(base_content));
    EXPECT_TRUE(state->objects.contains(child_content));
    EXPECT_FALSE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, A6_SharedContentAcrossMultiplePathsProtected) {
    const auto commit2 = make_commit(1, {commit_id(commit)}, "file2", "live").value();
    add_commit(commit2, true);
    const auto o1 = add_orphan("orph_a6");

    reset_fake_traffic(*state);
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(state->objects.contains(live));
    EXPECT_FALSE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, A7_MixedCandidatesRemovesOnlyContent) {
    const auto o1 = add_orphan("orph1");
    // Add extra redundant commit variant
    const auto extra_variant = add_commit(commit, false);
    ASSERT_TRUE(state->objects.contains(object_path(extra_variant)));

    reset_fake_traffic(*state);
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->content_candidates, 1U);
    EXPECT_EQ(res->removed_content, 1U);
    EXPECT_EQ(res->pending_commit_variants, 1U);

    // Orphan content was deleted
    EXPECT_FALSE(state->objects.contains(o1));
    // Commit variant MUST remain intact
    EXPECT_TRUE(state->objects.contains(object_path(extra_variant)));
}

TEST_F(GcContentRemovalTest, A8_CommitVariantsRemainIntact) {
    const auto extra_v1 = add_commit(commit, false);
    const auto extra_v2 = add_commit(commit, false);
    const auto o1 = add_orphan("orph_a8");

    reset_fake_traffic(*state);
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->content_candidates, 1U);
    EXPECT_EQ(res->pending_commit_variants, 2U);
    EXPECT_TRUE(state->objects.contains(object_path(head)));
    EXPECT_TRUE(state->objects.contains(object_path(extra_v1)));
    EXPECT_TRUE(state->objects.contains(object_path(extra_v2)));
}

TEST_F(GcContentRemovalTest, A9_VariableListingOrderDoesNotAffectOutcome) {
    const auto o1 = add_orphan("a_orph");
    const auto o2 = add_orphan("z_orph");
    state->reverse_listing = true;

    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->content_candidates, 2U);
    EXPECT_EQ(res->removed_content, 2U);
    EXPECT_FALSE(state->objects.contains(o1));
    EXPECT_FALSE(state->objects.contains(o2));
}

TEST_F(GcContentRemovalTest, A10_NoCopyOrQuarantineOperations) {
    add_orphan("orph_a10");
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(state->copy_count, 0U);
    EXPECT_EQ(state->copy_batch_count, 0U);
    EXPECT_EQ(state->quarantine_payload_put_count, 0U);
    EXPECT_EQ(state->quarantine_metadata_put_count, 0U);
}

// ============================================================================
// Grupo B — Barreiras e writers
// ============================================================================

TEST_F(GcContentRemovalTest, B1_ActiveWriterBlocksRemoval) {
    const auto o1 = add_orphan("orph_b1");
    state->objects[layout.writers_prefix + std::string(32, 'a')] = {'w'};

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::WriterPresent);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, B2_AbandonedWriterBlocksRemoval) {
    const auto o1 = add_orphan("orph_b2");
    state->objects[layout.writers_prefix + std::string(32, 'b')] = {'w'};

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::WriterPresent);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, B3_PreexistingBarrierBlocksAcquisition) {
    const auto o1 = add_orphan("orph_b3");
    state->objects[layout.barrier_identifier] = {'f', 'o', 'r', 'e', 'i', 'g', 'n'};

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::BarrierAcquisition);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, B4_BarrierReplacedBeforeRemovalBlocksMutation) {
    const auto o1 = add_orphan("orph_b4");
    between_observations = [this] {
        state->objects[layout.barrier_identifier] = {'s', 't', 'o', 'l', 'e', 'n'};
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::OwnershipLost);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, B5_OwnershipLostDuringExecutionStopsRemainingCandidates) {
    const auto o1 = add_orphan("orph_b5_1");
    const auto o2 = add_orphan("orph_b5_2");
    const auto o3 = add_orphan("orph_b5_3");

    before_content_remove = [this](std::string_view) {
        if (removed_identifiers.size() == 1) {
            // After 1st removal, steal barrier
            state->objects[layout.barrier_identifier] = {'s', 't', 'o', 'l', 'e', 'n'};
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::OwnershipLost);
    EXPECT_EQ(res.error().removed_content, 1U);
    // Remaining candidates were NOT removed
    EXPECT_EQ(removed_identifiers.size(), 1U);
}

TEST_F(GcContentRemovalTest, B6_WriterObservedDuringExecutionStopsRemainingCandidates) {
    const auto o1 = add_orphan("orph_b6_1");
    const auto o2 = add_orphan("orph_b6_2");

    before_content_remove = [this](std::string_view) {
        if (removed_identifiers.size() == 1) {
            state->objects[layout.writers_prefix + std::string(32, 'c')] = {'w'};
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::WriterPresent);
    EXPECT_EQ(res.error().removed_content, 1U);
    EXPECT_EQ(removed_identifiers.size(), 1U);
}

TEST_F(GcContentRemovalTest, B7_OwnershipVerificationFailureStopsNewRemovals) {
    const auto o1 = add_orphan("orph_b7_1");
    const auto o2 = add_orphan("orph_b7_2");

    before_content_remove = [this](std::string_view) {
        if (removed_identifiers.size() == 1) {
            state->fail_get_identifier = layout.barrier_identifier;
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::OwnershipLost);
    EXPECT_EQ(res.error().removed_content, 1U);
}

TEST_F(GcContentRemovalTest, B8_BarrierHeldDuringAllDestructiveOperations) {
    add_orphan("orph_b8");
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    // In SetUp(), on_operation verified EXPECT_TRUE(objects.contains(barrier_id)) on every content removal
}

TEST_F(GcContentRemovalTest, B9_BarrierReleasedAfterProcessing) {
    add_orphan("orph_b9");
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcContentRemovalTest, B10_CleanupFailureFailsGracefully) {
    add_orphan("orph_b10");
    state->fail_remove_identifier = layout.barrier_identifier;

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::BarrierRelease);
    EXPECT_EQ(res.error().removed_content, 1U);
}

// ============================================================================
// Grupo C — Alcançabilidade
// ============================================================================

TEST_F(GcContentRemovalTest, C1_HeadContentProtected) {
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(state->objects.contains(live));
}

TEST_F(GcContentRemovalTest, C2_AncestorContentProtected) {
    const auto base_commit = make_commit(0, {}, "base_file", "base_data").value();
    add_commit(base_commit, false);
    const auto base_cnt = content("base_data");
    state->objects[base_cnt] = {'d'};

    const auto child_commit = make_commit(1, {commit_id(base_commit)}, "child_file", "child_data").value();
    add_commit(child_commit, true);
    const auto child_cnt = content("child_data");
    state->objects[child_cnt] = {'d'};

    reset_fake_traffic(*state);
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(state->objects.contains(base_cnt));
    EXPECT_TRUE(state->objects.contains(child_cnt));
}

TEST_F(GcContentRemovalTest, C3_HeadChangeBetweenSnapshotsPreventsRemoval) {
    const auto o1 = add_orphan("orph_c3");
    between_observations = [this] {
        const auto new_commit = make_commit(1, {commit_id(commit)}, "c3", "live").value();
        add_commit(new_commit, true);
        reset_fake_traffic(*state);
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::SnapshotChanged);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, C4_ReachabilityChangeBetweenSnapshotsPreventsRemoval) {
    const auto o1 = add_orphan("orph_c4");
    between_observations = [this] {
        const auto new_commit = make_commit(1, {commit_id(commit)}, "new_file", "new_live").value();
        add_commit(new_commit, true);
        state->objects[content("new_live")] = {'n'};
        reset_fake_traffic(*state);
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::SnapshotChanged);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, C5_CandidateClassificationChangeBetweenSnapshotsPreventsRemoval) {
    const auto o1 = add_orphan("orph_c5");
    between_observations = [this, &o1] {
        state->objects.erase(o1);
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::SnapshotChanged);
}

TEST_F(GcContentRemovalTest, C6_InvalidHistoryPreventsRemoval) {
    const auto o1 = add_orphan("orph_c6");
    // Point to non-existent parent commit
    const auto broken_commit = make_commit(1, {std::string(64, 'f')}, "f", "l").value();
    add_commit(broken_commit, true);
    reset_fake_traffic(*state);

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Observation);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, C7_RequiredCommitVariantPreserved) {
    const auto o1 = add_orphan("orph_c7");
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(head)));
}

TEST_F(GcContentRemovalTest, C8_ProtectedContentPhysicallyMissingFailsSnapshot) {
    state->objects.erase(live); // Live content missing
    const auto o1 = add_orphan("orph_c8");

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Observation);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, C9_UnknownStorageObjectPreventsUnsafeSelection) {
    const auto o1 = add_orphan("orph_c9");
    state->objects["random/unknown/file.bin"] = {'x'};

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Observation);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, C10_CandidateNoLongerEligibleNotRemoved) {
    const auto o1 = add_orphan("orph_c10");
    between_observations = [this] {
        // Between observations 1 and 2, a new commit references o1, making it protected
        const auto new_commit = make_commit(1, {commit_id(commit)}, "c10_file", "orph_c10").value();
        add_commit(new_commit, true);
        reset_fake_traffic(*state);
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::SnapshotChanged);
    EXPECT_TRUE(state->objects.contains(o1));
    EXPECT_TRUE(state->objects.contains(live));
}

// ============================================================================
// Grupo D — Falhas de transporte
// ============================================================================

TEST_F(GcContentRemovalTest, D1_InitialListFailure) {
    const auto o1 = add_orphan("orph_d1");
    state->on_operation = [this](FakeState& current, std::string_view operation, std::string_view id) {
        if (operation == "before_list" && current.full_list_count == 0) {
            current.fail_list = kasumi::transport::ErrorCode::Io;
            current.fail_list_at = current.list_count + 1;
        }
        if (operation == "before_remove" && id != layout.barrier_identifier) {
            removed_identifiers.push_back(std::string(id));
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Observation);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, D2_SecondObservationFailure) {
    const auto o1 = add_orphan("orph_d2");
    between_observations = [this] {
        state->fail_list = kasumi::transport::ErrorCode::Io;
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Observation);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, D3_CandidatePresenceFailure) {
    const auto o1 = add_orphan("orph_d3");
    storage.storage.presence = [](void* context, std::string_view id) -> kasumi::transport::PresenceResult {
        const auto lay = history::derive_remote_layout(test_key());
        if (id != lay.barrier_identifier) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Io,
                .message = "injected candidate presence failure"
            });
        }
        return fake_presence(context, id);
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Observation);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, D4_RemoveFailureBeforeMutation) {
    const auto o1 = add_orphan("orph_d4");
    state->fail_remove_at = 1;

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::RemovalFailure);
    EXPECT_EQ(res.error().removed_content, 0U);
    // Under transport contract, Io error during remove cannot exclude mutation
    EXPECT_TRUE(res.error().uncertain_mutation);
    EXPECT_TRUE(state->objects.contains(o1));
}

TEST_F(GcContentRemovalTest, D5_RemoveAppliedWithTransportError) {
    const auto o1 = add_orphan("orph_d5");
    // Object is deleted from storage, but remove reports transport error
    state->remove_then_fail_identifier = o1;

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::RemovalFailure);
    EXPECT_TRUE(res.error().uncertain_mutation);
}

TEST_F(GcContentRemovalTest, D6_AlreadyAbsentDoesNotIncrementRemovedContent) {
    const auto o1 = add_orphan("orph_d6");
    // Erase object right before remove is invoked so fake_remove returns AlreadyAbsent
    before_content_remove = [this, o1](std::string_view id) {
        if (id == o1) {
            state->objects.erase(o1);
        }
    };

    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->content_candidates, 1U);
    EXPECT_EQ(res->removed_content, 0U);
    EXPECT_EQ(res->already_absent, 1U);
}

TEST_F(GcContentRemovalTest, D7_FailureOnFirstCandidate) {
    const auto o1 = add_orphan("orph_d7_1");
    const auto o2 = add_orphan("orph_d7_2");
    state->fail_remove_at = 1;

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::RemovalFailure);
    EXPECT_EQ(res.error().removed_content, 0U);
    EXPECT_TRUE(state->objects.contains(o1));
    EXPECT_TRUE(state->objects.contains(o2));
}

TEST_F(GcContentRemovalTest, D8_FailureAfterConfirmedRemovals) {
    const auto o1 = add_orphan("orph_d8_1");
    const auto o2 = add_orphan("orph_d8_2");
    const auto o3 = add_orphan("orph_d8_3");

    before_content_remove = [this](std::string_view id) {
        if (removed_identifiers.size() == 2) {
            state->fail_remove_identifier = std::string(id);
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::RemovalFailure);
    EXPECT_EQ(res.error().removed_content, 1U);
    // 3rd candidate never attempted
    EXPECT_EQ(removed_identifiers.size(), 2U);
}

TEST_F(GcContentRemovalTest, D9_RemovalErrorWithBarrierReleaseErrorPreservesBoth) {
    add_orphan("orph_d9");
    state->fail_remove_at = 1;
    before_content_remove = [this](std::string_view) {
        state->fail_remove_identifier = layout.barrier_identifier;
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::RemovalFailure);
    ASSERT_TRUE(res.error().cleanup_error.has_value());
}

TEST_F(GcContentRemovalTest, D10_UncertainResultDoesNotBlindlyRetry) {
    const auto o1 = add_orphan("orph_d10");
    state->remove_then_fail_identifier = o1;

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::RemovalFailure);
    EXPECT_TRUE(res.error().uncertain_mutation);
    // Verified: only one attempt was made
    EXPECT_EQ(removed_identifiers.size(), 1U);
}

TEST_F(GcContentRemovalTest, D11_MidProcessingFailureDoesNotAuthorizeFollowingCandidates) {
    const auto o1 = add_orphan("orph_d11_1");
    const auto o2 = add_orphan("orph_d11_2");
    const auto o3 = add_orphan("orph_d11_3");

    before_content_remove = [this](std::string_view id) {
        if (removed_identifiers.size() == 2) {
            state->fail_remove_identifier = std::string(id);
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().removed_content, 1U);
    EXPECT_EQ(removed_identifiers.size(), 2U);
    for (const auto& id : {o1, o2, o3}) {
        if (std::ranges::find(removed_identifiers, id) == removed_identifiers.end()) {
            EXPECT_TRUE(state->objects.contains(id));
        }
    }
}

TEST_F(GcContentRemovalTest, D12_ContradictoryTransportResultFailsClosed) {
    add_orphan("orph_d12");
    storage.storage.remove = [](void*, std::string_view) -> kasumi::transport::RemovalResult {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::ProtocolFailure,
            .message = "contradictory transport status"
        });
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::RemovalFailure);
    EXPECT_EQ(res.error().removed_content, 0U);
}

TEST_F(GcContentRemovalTest, D13_RemoveFailureDoesNotTriggerSupplementaryPresenceProbe) {
    const auto o1 = add_orphan("orph_d13_1");
    const auto o2 = add_orphan("orph_d13_2");
    const auto first = std::min(o1, o2);
    const auto second = std::max(o1, o2);

    state->fail_remove_identifier = first;

    std::size_t pre_remove_probes = 0;
    std::size_t post_remove_probes = 0;
    bool remove_attempted = false;

    state->on_operation = [&](FakeState&, std::string_view op, std::string_view id) {
        if (op == "before_remove" && id != layout.barrier_identifier) {
            removed_identifiers.push_back(std::string(id));
            if (id == first) {
                remove_attempted = true;
            }
        }
        if (op == "presence" && id == first) {
            if (remove_attempted) {
                ++post_remove_probes;
            } else {
                ++pre_remove_probes;
            }
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::RemovalFailure);
    EXPECT_TRUE(res.error().uncertain_mutation);
    EXPECT_EQ(res.error().removed_content, 0U);
    EXPECT_EQ(res.error().cause.code, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(res.error().cause.object_identifier, first);

    // Exactly one pre-remove presence check occurred for eligibility
    EXPECT_EQ(pre_remove_probes, 1U);
    // Strict contract: NO supplementary presence probe is triggered after remove failure
    EXPECT_EQ(post_remove_probes, 0U);

    // Second candidate never processed
    EXPECT_EQ(removed_identifiers.size(), 1U);
    EXPECT_TRUE(state->objects.contains(second));
    // Barrier cleaned up
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcContentRemovalTest, D14_RemoveAppliedWithLostResponseFlagsUncertainMutation) {
    const auto o1 = add_orphan("orph_d14_1");
    const auto o2 = add_orphan("orph_d14_2");
    const auto first = std::min(o1, o2);
    const auto second = std::max(o1, o2);
    state->remove_then_fail_identifier = first;

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::RemovalFailure);
    EXPECT_TRUE(res.error().uncertain_mutation);
    EXPECT_EQ(res.error().removed_content, 0U);
    EXPECT_FALSE(state->objects.contains(first));
    // 2nd candidate not processed
    EXPECT_EQ(removed_identifiers.size(), 1U);
    EXPECT_TRUE(state->objects.contains(second));
}

TEST_F(GcContentRemovalTest, D15_PreRemovePresenceObservationDoesNotClearUncertainMutation) {
    const auto o1 = add_orphan("orph_d15");
    state->fail_remove_identifier = o1;
    ASSERT_TRUE(state->objects.contains(o1));

    std::size_t pre_remove_probes = 0;
    std::size_t post_remove_probes = 0;
    bool remove_attempted = false;

    state->on_operation = [&](FakeState&, std::string_view op, std::string_view id) {
        if (op == "before_remove" && id != layout.barrier_identifier) {
            removed_identifiers.push_back(std::string(id));
            if (id == o1) {
                remove_attempted = true;
            }
        }
        if (op == "presence" && id == o1) {
            if (remove_attempted) {
                ++post_remove_probes;
            } else {
                ++pre_remove_probes;
            }
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::RemovalFailure);
    // Prior observation of Present does not eliminate uncertainty on remove failure
    EXPECT_TRUE(res.error().uncertain_mutation);
    EXPECT_EQ(res.error().cause.code, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(res.error().cause.object_identifier, o1);

    // Only the legitimate pre-removal presence check was executed
    EXPECT_EQ(pre_remove_probes, 1U);
    // No supplementary probe executed after failure
    EXPECT_EQ(post_remove_probes, 0U);
    // Cleanup was executed
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

// ============================================================================
// Grupo E — Interrupção e reexecução
// ============================================================================

TEST_F(GcContentRemovalTest, E1_CancellationBeforeFirstRemoval) {
    add_orphan("orph_e1");
    cancellation::request();

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Cancelled);
    EXPECT_EQ(res.error().removed_content, 0U);
}

TEST_F(GcContentRemovalTest, E2_CancellationAfterConfirmedRemoval) {
    add_orphan("orph_e2_1");
    add_orphan("orph_e2_2");

    before_content_remove = [this](std::string_view) {
        if (removed_identifiers.size() == 1) {
            cancellation::request();
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Cancelled);
    EXPECT_EQ(res.error().removed_content, 1U);
}

TEST_F(GcContentRemovalTest, E3_CancellationDuringRemoveFailurePreservesTransportErrorAndUncertainty) {
    const auto o1 = add_orphan("orph_e3");
    before_content_remove = [this, o1](std::string_view id) {
        if (id == o1) {
            cancellation::request();
            state->fail_remove_identifier = std::string(id);
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Cancelled);
    EXPECT_TRUE(res.error().uncertain_mutation);
    EXPECT_EQ(res.error().cause.code, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(res.error().cause.object_identifier, o1);
    EXPECT_TRUE(res.error().cause.detail.find("injected remove failure") != std::string::npos);
}

TEST_F(GcContentRemovalTest, E4_SecondRunRemovesRemainingOrphans) {
    const auto o1 = add_orphan("orph_e4_1");
    const auto o2 = add_orphan("orph_e4_2");

    // Run 1: cancel after 1st
    before_content_remove = [this](std::string_view) {
        if (removed_identifiers.size() == 1) {
            cancellation::request();
        }
    };

    auto res1 = run_removal();
    ASSERT_FALSE(res1.has_value());
    EXPECT_EQ(res1.error().code, Failure::Cancelled);
    EXPECT_EQ(res1.error().removed_content, 1U);
    const auto remaining = (removed_identifiers[0] == o1) ? o2 : o1;
    EXPECT_TRUE(state->objects.contains(remaining));

    // Run 2: fresh run, resets cancellation, processes remaining
    cancellation::reset();
    before_content_remove = nullptr;
    removed_identifiers.clear();

    auto res2 = run_removal();
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2->content_candidates, 1U);
    EXPECT_EQ(res2->removed_content, 1U);
    EXPECT_FALSE(state->objects.contains(remaining));
}

TEST_F(GcContentRemovalTest, E5_ThirdRunAfterCompletionRemovesNothing) {
    add_orphan("orph_e5");
    auto res1 = run_removal();
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(res1->removed_content, 1U);

    auto res2 = run_removal();
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2->content_candidates, 0U);
    EXPECT_EQ(res2->removed_content, 0U);
}

TEST_F(GcContentRemovalTest, E6_ReexecutionCreatesNewBarrierAndObservations) {
    add_orphan("orph_e6_1");
    auto res1 = run_removal();
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(state->full_list_count, 2U);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
    ASSERT_EQ(barrier_puts.size(), 1U);
    const auto barrier1 = barrier_puts[0];

    add_orphan("orph_e6_2");
    auto res2 = run_removal();
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(state->full_list_count, 4U);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
    ASSERT_EQ(barrier_puts.size(), 2U);
    const auto barrier2 = barrier_puts[1];

    // Tokens/identities are strictly distinct
    EXPECT_NE(barrier1, barrier2);
}

TEST_F(GcContentRemovalTest, E7_NoPreviousAuthorizationReused) {
    const auto o1 = add_orphan("orph_e7_1");
    auto res1 = run_removal();
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(res1->content_candidates, 1U);
    EXPECT_EQ(res1->removed_content, 1U);
    EXPECT_FALSE(state->objects.contains(o1));

    // Between executions, modify inventory: add new orphan and add newly protected content
    const auto o2 = add_orphan("orph_e7_2");
    const auto new_live = content("new_live");
    state->objects[new_live] = {'n', 'e', 'w'};
    const auto new_commit = make_commit(1, {commit_id(commit)}, "new_file", "new_live").value();
    add_commit(new_commit, true);
    reset_fake_traffic(*state);

    // Second execution performs fresh analysis
    auto res2 = run_removal();
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2->content_candidates, 1U);
    EXPECT_EQ(res2->removed_content, 1U);
    EXPECT_FALSE(state->objects.contains(o2));
    EXPECT_TRUE(state->objects.contains(new_live));
    EXPECT_TRUE(state->objects.contains(live));
}

TEST_F(GcContentRemovalTest, E8_PartialFailurePreservesAuthenticatedHistory) {
    add_orphan("orph_e8_1");
    add_orphan("orph_e8_2");

    before_content_remove = [this](std::string_view id) {
        if (removed_identifiers.size() == 2) {
            state->fail_remove_identifier = std::string(id);
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    // Commits, markers, and live content remain completely intact
    EXPECT_TRUE(state->objects.contains(object_path(head)));
    EXPECT_TRUE(state->objects.contains(marker_path(head)));
    EXPECT_TRUE(state->objects.contains(live));
}

TEST_F(GcContentRemovalTest, E9_CancellationWithRemoveFailureAndCleanupFailurePreservesBoth) {
    const auto o1 = add_orphan("orph_e9");
    state->fail_remove_at = 1;
    before_content_remove = [this](std::string_view) {
        cancellation::request();
        state->fail_remove_identifier = layout.barrier_identifier;
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Cancelled);
    EXPECT_TRUE(res.error().uncertain_mutation);
    EXPECT_EQ(res.error().cause.code, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(res.error().cause.object_identifier, o1);
    ASSERT_TRUE(res.error().cleanup_error.has_value());
    EXPECT_EQ(res.error().cleanup_error->code, integrity::ErrorCode::TransportFailure);
}

TEST_F(GcContentRemovalTest, E10_CancellationAfterConfirmedRemovalPreservesCountAndCertainty) {
    const auto o1 = add_orphan("orph_e10_1");
    const auto o2 = add_orphan("orph_e10_2");

    before_content_remove = [this](std::string_view) {
        if (removed_identifiers.size() == 1) {
            cancellation::request();
        }
    };

    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, Failure::Cancelled);
    EXPECT_EQ(res.error().removed_content, 1U);
    // First removal was confirmed, so uncertain_mutation must be false
    EXPECT_FALSE(res.error().uncertain_mutation);
    EXPECT_FALSE(state->objects.contains(o1));
    EXPECT_TRUE(state->objects.contains(o2));
}

// ============================================================================
// Grupo F — Isolamento de mutações
// ============================================================================

TEST_F(GcContentRemovalTest, F1_ZeroUnauthorizedMutationsOnSuccess) {
    add_orphan("orph_f1");
    auto res = run_removal();
    ASSERT_TRUE(res.has_value());
    // TearDown verifies all mutation counts
}

TEST_F(GcContentRemovalTest, F2_ZeroUnauthorizedMutationsOnFailure) {
    add_orphan("orph_f2");
    state->fail_remove_at = 1;
    auto res = run_removal();
    ASSERT_FALSE(res.has_value());
    // TearDown verifies all mutation counts
}

} // namespace
