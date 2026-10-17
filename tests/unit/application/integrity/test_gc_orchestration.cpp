#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "kasumi/test/history_storage.hpp"
#include "platform/cancellation.hpp"

namespace {

namespace integrity = kasumi::application::integrity;
namespace history = kasumi::application::history_storage;
namespace protocol = history::maintenance_protocol;
namespace cancellation = kasumi::platform::cancellation;
using Failure = integrity::GcAnalysisErrorCode;

class GcOrchestrationTest : public ::testing::Test {
protected:
    TempWorkspace workspace = kasumi::test::make_temp_workspace("gc-analysis");
    FakeState* state = nullptr;
    kasumi::transport::Transport storage = make_fake_transport(state);
    history::RemoteLayout layout = history::derive_remote_layout(test_key());
    Commit commit = make_commit(0, {}, "file", "live").value();
    HeadReference head;
    std::string live = content("live");
    std::function<void()> between_observations;

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
        storage.storage.remove = [](void* context, std::string_view id) {
            EXPECT_EQ(id, history::derive_remote_layout(test_key()).barrier_identifier);
            return fake_remove(context, id);
        };
        storage.storage.list = [](void* context) {
            auto* current = fake_state(context);
            if (current->on_operation) current->on_operation(*current, "before_list", {});
            return fake_list(context);
        };
        storage.storage.put_batch = fake_put_batch;
        storage.storage.copy_batch = fake_copy_batch;
        storage.storage.remove_batch = fake_remove_batch;
        state->on_operation = [this](FakeState& current, std::string_view operation, std::string_view) {
            if (operation == "before_list" && current.full_list_count == 1 && between_observations)
                between_observations();
        };
    }

    void TearDown() override {
        cancellation::reset();
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

    auto analyze() {
        return integrity::analyze_gc_under_barrier(
            storage, test_key(), kasumi::test::workspace_root(workspace));
    }

    void expect_failure(Failure code) {
        const auto result = analyze();
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, code) << result.error().cause.detail;
    }

    void writer() { state->objects[layout.writers_prefix + std::string(32, 'a')] = {'w'}; }
    void replaced_barrier() { replace_barrier_contents(state, layout.barrier_identifier); }
};

TEST_F(GcOrchestrationTest, IndependentObservationsReleaseBeforeReturningDiagnosticReport) {
    const auto before = state->objects;
    const auto result = analyze();
    ASSERT_TRUE(result.has_value()) << result.error().cause.detail;
    EXPECT_TRUE(result->candidates.empty());
    EXPECT_EQ(result->logical_heads, std::vector<std::string>{head.commit_id});
    EXPECT_EQ(state->full_list_count, 2U);
    EXPECT_EQ(state->marker_get_count, 2U);
    EXPECT_GE(state->commit_get_count, 2U);
    EXPECT_EQ(state->put_count, 1U);
    EXPECT_EQ(state->remove_count, 1U);
    EXPECT_EQ(state->objects, before);
}

TEST_F(GcOrchestrationTest, MixedCandidatesAndReorderedListingRemainDeterministic) {
    const auto extra = add_commit(commit, false);
    const auto orphan = content("orphan");
    state->objects[orphan] = {'o'};
    reset_fake_traffic(*state);
    between_observations = [&] { state->reverse_listing = true; };
    const auto before = state->objects;
    const auto result = analyze();
    ASSERT_TRUE(result.has_value()) << result.error().cause.detail;
    EXPECT_EQ(result->candidates.size(), 2U);
    EXPECT_NE(std::ranges::find(result->candidates,
        integrity::GcCandidate{orphan, integrity::GcCandidateKind::Content}), result->candidates.end());
    EXPECT_NE(std::ranges::find(result->candidates,
        integrity::GcCandidate{object_path(extra), integrity::GcCandidateKind::CommitVariant}), result->candidates.end());
    EXPECT_EQ(state->objects, before);
}

TEST_F(GcOrchestrationTest, ActiveAndAbandonedWritersBothBlockWithoutPublishing) {
    for (const auto& bytes : {protocol::testing::format_payload("writer", std::string(32, 'a')),
                              std::vector<std::uint8_t>{'a', 'b', 'a', 'n', 'd', 'o', 'n', 'e', 'd'}}) {
        state->objects[layout.writers_prefix + std::string(32, 'a')] = bytes;
        const auto before = state->objects;
        expect_failure(Failure::WriterPresent);
        EXPECT_EQ(state->objects, before);
        EXPECT_EQ(state->put_count, 0U);
    }
}

TEST_F(GcOrchestrationTest, ExistingForeignBarrierIsNeverOverwritten) {
    state->objects[layout.barrier_identifier] = {'f'};
    const auto before = state->objects;
    expect_failure(Failure::BarrierAcquisition);
    EXPECT_EQ(state->objects, before);
    EXPECT_EQ(state->put_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST_F(GcOrchestrationTest, WriterListingFailureIsNotAbsence) {
    state->fail_writer_list = true;
    expect_failure(Failure::Preconditions);
    EXPECT_EQ(state->put_count, 0U);
}

TEST_F(GcOrchestrationTest, InvalidWriterIdentityBlocksWithoutMutation) {
    state->objects[layout.writers_prefix + "invalid"] = {'w'};
    expect_failure(Failure::Preconditions);
    EXPECT_EQ(state->put_count, 0U);
}

TEST_F(GcOrchestrationTest, WriterDuringAcquisitionBlocksAndReleasesOwnBarrier) {
    state->on_operation = [&](FakeState&, std::string_view operation, std::string_view) {
        if (operation == "after_put") writer();
    };
    expect_failure(Failure::WriterPresent);
    EXPECT_EQ(state->full_list_count, 0U);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcOrchestrationTest, WriterAfterSecondObservationInvalidatesAnalysis) {
    state->on_operation = [&](FakeState& current, std::string_view operation, std::string_view) {
        if (operation == "after_list" && current.full_list_count == 2) writer();
    };
    expect_failure(Failure::WriterPresent);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcOrchestrationTest, WriterObservedOnlyBySnapshotStillBlocks) {
    storage.storage.list = [](void* context) {
        auto listed = fake_list(context);
        if (listed) listed->push_back(
            history::derive_remote_layout(test_key()).writers_prefix + std::string(32, 'a'));
        return listed;
    };
    const auto before = state->objects;
    expect_failure(Failure::WriterPresent);
    EXPECT_EQ(state->objects, before);
}

TEST_F(GcOrchestrationTest, ReplacedBarrierAfterObservationsIsPreserved) {
    state->on_operation = [&](FakeState& current, std::string_view operation, std::string_view) {
        if (operation == "after_list" && current.full_list_count == 2) replaced_barrier();
    };
    expect_failure(Failure::OwnershipLost);
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_EQ(state->objects.at(layout.barrier_identifier),
              (std::vector<std::uint8_t>{'r','e','p','l','a','c','e','d'}));
}

TEST_F(GcOrchestrationTest, BarrierSubstitutionDuringAcquisitionNeverGetsRemoved) {
    state->on_operation = [&](FakeState&, std::string_view operation, std::string_view) {
        if (operation == "after_put") replaced_barrier();
    };
    expect_failure(Failure::BarrierAcquisition);
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcOrchestrationTest, PublicationFailureNeverRetriesBlindly) {
    state->fail_put_identifier = layout.barrier_identifier;
    expect_failure(Failure::BarrierAcquisition);
    EXPECT_EQ(state->put_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST_F(GcOrchestrationTest, AppliedPublicationErrorRetainsUnconfirmedBarrier) {
    state->put_then_fail_identifier = layout.barrier_identifier;
    expect_failure(Failure::BarrierAcquisition);
    EXPECT_EQ(state->put_count, 1U);
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcOrchestrationTest, ReadbackErrorRetainsUnconfirmedBarrier) {
    state->fail_get_identifier = layout.barrier_identifier;
    expect_failure(Failure::BarrierAcquisition);
    EXPECT_EQ(state->full_list_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST_F(GcOrchestrationTest, FailedBarrierPresenceNeverPublishes) {
    state->fail_barrier_presence = true;
    expect_failure(Failure::BarrierAcquisition);
    EXPECT_EQ(state->put_count, 0U);
}

TEST_F(GcOrchestrationTest, FirstAndSecondObservationErrorsPreserveData) {
    for (const std::size_t observation : {1U, 2U}) {
        reset_fake_traffic(*state);
        state->on_operation = [=](FakeState& current, std::string_view operation, std::string_view) {
            if (operation == "before_list" && current.full_list_count + 1 == observation) {
                current.fail_list = kasumi::transport::ErrorCode::Io;
                current.fail_list_at = current.list_count + 1;
            }
        };
        const auto before = state->objects;
        expect_failure(Failure::Observation);
        EXPECT_EQ(state->objects, before);
        state->fail_list.reset();
    }
}

TEST_F(GcOrchestrationTest, HeadReadFailureAndInvalidAuthenticatedHistoryAbort) {
    state->fail_marker_get = true;
    expect_failure(Failure::Observation);
    state->fail_marker_get = false;
    state->objects[object_path(head)][0] ^= 1;
    expect_failure(Failure::Observation);
}

TEST_F(GcOrchestrationTest, CleanupFailurePreventsSuccess) {
    state->fail_remove_identifier = layout.barrier_identifier;
    expect_failure(Failure::BarrierRelease);
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcOrchestrationTest, PrimaryErrorAndCleanupErrorRemainSeparate) {
    state->fail_marker_get = true;
    state->fail_remove_identifier = layout.barrier_identifier;
    const auto result = analyze();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::Observation);
    EXPECT_TRUE(result.error().cleanup_error.has_value());
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcOrchestrationTest, CancellationPreservesTheTransportFailureThatTriggeredIt) {
    for (const bool acquiring : {true, false}) {
        cancellation::reset();
        state->objects.erase(layout.barrier_identifier);
        if (acquiring) {
            state->put_then_fail_identifier = layout.barrier_identifier;
            state->on_operation = [](FakeState&, std::string_view operation, std::string_view) {
                if (operation == "after_put") cancellation::request();
            };
        } else {
            state->on_operation = {};
            storage.storage.list = [](void*) -> kasumi::transport::ListingResult {
                cancellation::request();
                return std::unexpected(kasumi::transport::Error{
                    .code = kasumi::transport::ErrorCode::Cancelled,
                    .message = "cancelled LIST failure"});
            };
        }
        const auto result = analyze();
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, Failure::Cancelled);
        EXPECT_NE(result.error().cause.detail.find(
            acquiring ? "injected put failure" : "cancelled LIST failure"), std::string::npos);
    }
}

TEST_F(GcOrchestrationTest, UncertainPostRemovalPresencePreventsSuccess) {
    state->on_operation = [&](FakeState& current, std::string_view operation, std::string_view) {
        if (operation == "before_remove")
            current.fail_presence_after_removal_identifier = layout.barrier_identifier;
    };
    expect_failure(Failure::BarrierRelease);
}

TEST_F(GcOrchestrationTest, AlreadyAbsentRemovalCannotConfirmOwnedRelease) {
    storage.storage.remove = [](void* context, std::string_view id) -> kasumi::transport::RemovalResult {
        auto* current = fake_state(context);
        current->objects.erase(std::string{id});
        ++current->remove_count;
        return kasumi::transport::Removal::AlreadyAbsent;
    };
    expect_failure(Failure::BarrierRelease);
}

TEST_F(GcOrchestrationTest, AppliedRemoveErrorRequiresConfirmedAbsence) {
    state->remove_then_fail_identifier = layout.barrier_identifier;
    const auto result = analyze();
    ASSERT_TRUE(result.has_value()) << result.error().cause.detail;
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcOrchestrationTest, OwnershipReadErrorDuringCleanupNeverRemoves) {
    state->on_operation = [&](FakeState& current, std::string_view operation, std::string_view) {
        if (operation == "after_prefix_list" && current.full_list_count == 2) {
            current.fail_get_identifier = layout.barrier_identifier;
            current.fail_get_identifier_after_count = 1;
            current.fail_get_identifier_call_count = 0;
        }
    };
    expect_failure(Failure::BarrierRelease);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST_F(GcOrchestrationTest, SubsequentAttemptUsesFreshIdentity) {
    std::vector<std::vector<std::uint8_t>> tokens;
    state->on_operation = [&](FakeState& current, std::string_view operation, std::string_view) {
        if (operation == "after_put") tokens.push_back(current.objects.at(layout.barrier_identifier));
    };
    ASSERT_TRUE(analyze().has_value());
    ASSERT_TRUE(analyze().has_value());
    ASSERT_EQ(tokens.size(), 2U);
    EXPECT_NE(tokens[0], tokens[1]);
}

TEST_F(GcOrchestrationTest, PhysicalHashOwnershipPathAlsoCompletes) {
    state->physical_hash_supported = true;
    ASSERT_TRUE(analyze().has_value());
    EXPECT_EQ(state->remove_count, 1U);
}

TEST_F(GcOrchestrationTest, EpochAndMarkerBytesAreAuthenticatedAgain) {
    const auto sealed = history::epoch::seal(
        {.vault_id = std::string(64, 'a'), .sequence = 0, .issued_at = 1,
         .policy = {}, .anchors = {{head.commit_id, 0}}, .previous_epoch_id = {}},
        test_key()).value();
    const auto identifier = history::epoch_object(layout, sealed.reference);
    state->objects[identifier] = sealed.bytes;
    const auto before = state->objects;
    ASSERT_TRUE(analyze().has_value());
    EXPECT_EQ(state->objects, before);
    for (const auto& target : {identifier, marker_path(head)}) {
        state->objects = before;
        reset_fake_traffic(*state);
        between_observations = [&] { state->objects[target][0] ^= 1; };
        expect_failure(Failure::Observation);
        EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
        EXPECT_EQ(state->epoch_get_count, 2U);
    }
}

TEST_F(GcOrchestrationTest, NewValidEpochChangesTheObservedNamespace) {
    const auto sealed = history::epoch::seal(
        {.vault_id = std::string(64, 'a'), .sequence = 0, .issued_at = 1,
         .policy = {}, .anchors = {{head.commit_id, 0}}, .previous_epoch_id = {}},
        test_key()).value();
    between_observations = [&] {
        state->objects[history::epoch_object(layout, sealed.reference)] = sealed.bytes;
    };
    expect_failure(Failure::SnapshotChanged);
}

TEST_F(GcOrchestrationTest, ReplacementObservedDuringCleanupRemainsUntouched) {
    for (const std::size_t read : {4U, 5U}) {
        state->objects.erase(layout.barrier_identifier);
        reset_fake_traffic(*state);
        state->on_operation = [&](FakeState& current, std::string_view operation, std::string_view id) {
            if (operation == "before_get" && id == layout.barrier_identifier &&
                current.barrier_verification_count == read) replaced_barrier();
        };
        expect_failure(Failure::BarrierRelease);
        EXPECT_EQ(state->remove_count, 0U);
        EXPECT_EQ(state->objects.at(layout.barrier_identifier),
                  (std::vector<std::uint8_t>{'r','e','p','l','a','c','e','d'}));
    }
}

TEST_F(GcOrchestrationTest, InvalidWorkspaceAndTransportNeverMutate) {
    const auto path = kasumi::test::workspace_path(workspace, "not-directory");
    kasumi::test::write_text(path, "file");
    EXPECT_FALSE(integrity::analyze_gc_under_barrier(storage, test_key(), path));
    kasumi::transport::Transport invalid;
    EXPECT_FALSE(integrity::analyze_gc_under_barrier(
        invalid, test_key(), kasumi::test::workspace_root(workspace)));
    EXPECT_EQ(state->put_count, 0U);
}

TEST_F(GcOrchestrationTest, InitializationFailureStopsBeforeProtocol) {
    storage.storage.initialize = [](void*) -> kasumi::transport::Result {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io, .message = "initialize failed"});
    };
    expect_failure(Failure::Preconditions);
    EXPECT_EQ(state->put_count, 0U);
    EXPECT_EQ(state->list_count, 0U);
}

class GcChangedObservationTest : public GcOrchestrationTest,
                                public ::testing::WithParamInterface<int> {};

TEST_P(GcChangedObservationTest, NeverReportsStability) {
    const auto other = make_commit(0, {}, "other", "live").value();
    const auto other_ref = add_commit(other, false);
    const auto variant = add_commit(commit, false);
    const auto orphan = content("orphan");
    state->objects[orphan] = {'o'};
    const auto new_commit_bytes = state->objects.at(object_path(other_ref));
    if (GetParam() == 2) state->objects.erase(object_path(other_ref));
    reset_fake_traffic(*state);
    between_observations = [&] {
        switch (GetParam()) {
        case 0: state->objects[marker_path(other_ref)] = history::encode_marker(other_ref).value(); break;
        case 1: state->objects.erase(marker_path(head)); break;
        case 2: state->objects[object_path(other_ref)] = new_commit_bytes; break;
        case 3:
            state->objects.erase(marker_path(head));
            state->objects[marker_path(variant)] = history::encode_marker(variant).value();
            break;
        case 4: state->objects[content("new")] = {'n'}; break;
        case 5: state->objects.erase(live); break;
        case 6: state->objects["unknown"] = {'u'}; break;
        case 7: state->objects[marker_path(other_ref)] = history::encode_marker(other_ref).value(); break;
        case 8: state->objects.erase(orphan); state->objects[content("replacement")] = {'r'}; break;
        case 9: state->objects[history::epoch_object(layout, 0, std::string(64, 'a'))] = {'e'}; break;
        }
    };
    const auto result = analyze();
    ASSERT_FALSE(result.has_value());
    const bool invalid_inventory = GetParam() == 1 || GetParam() == 5 ||
                                   GetParam() == 6 || GetParam() == 9;
    EXPECT_EQ(result.error().code, invalid_inventory ? Failure::Observation : Failure::SnapshotChanged);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

INSTANTIATE_TEST_SUITE_P(HistoryContentAndProtocol, GcChangedObservationTest,
                        ::testing::Range(0, 10), ([](const auto& scenario) {
    constexpr std::string_view names[]{"NewHead", "RemovedHead", "NewCommit", "RequiredVariant",
        "NewContent", "RemovedContent", "UnknownObject", "CandidateBecomesProtected",
        "EqualCountsDifferentIds", "InvalidEpoch"};
    return std::string{names[scenario.param]};
}));

class GcCancellationTest : public GcOrchestrationTest,
                           public ::testing::WithParamInterface<int> {};

TEST_P(GcCancellationTest, CancellationNeverReturnsSuccessAndAttemptsCleanup) {
    const int point = GetParam();
    if (point == 0) cancellation::request();
    state->on_operation = [&](FakeState& current, std::string_view operation, std::string_view id) {
        if ((point == 1 && operation == "after_put") ||
            (point == 2 && operation == "before_get" && id == layout.barrier_identifier && current.barrier_verification_count == 1) ||
            (point == 3 && operation == "after_list" && current.full_list_count == 1) ||
            (point == 4 && operation == "after_list" && current.full_list_count == 2) ||
            (point == 5 && operation == "after_prefix_list" && current.full_list_count == 2) ||
            (point == 6 && operation == "before_remove")) cancellation::request();
    };
    expect_failure(Failure::Cancelled);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

INSTANTIATE_TEST_SUITE_P(ProtocolBoundaries, GcCancellationTest, ::testing::Range(0, 7));

} // namespace
