#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "kasumi/test/history_storage.hpp"

namespace {

namespace protocol = kasumi::application::history_storage::maintenance_protocol;
namespace history = kasumi::application::history_storage;

TEST(ManualWriterRemovalTest, RemovesOnlyTheSelectedListedWriter) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    const auto selected = layout.writers_prefix + std::string(32, 'a');
    const auto other = layout.writers_prefix + std::string(32, 'b');
    state->objects[selected] = {'a'};
    state->objects[other] = {'b'};
    state->objects["unrelated/object"] = {'d'};
    auto expected = state->objects;
    expected.erase(selected);

    const auto removed = protocol::remove_writer(storage, layout, selected);

    ASSERT_TRUE(removed.has_value()) << (removed ? "" : removed.error().detail);
    EXPECT_EQ(state->objects, expected);
}

TEST(ManualWriterRemovalTest, MissingAndStorageFailuresAreNotSuccess) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    const auto selected = layout.writers_prefix + std::string(32, 'a');
    const auto missing = protocol::remove_writer(storage, layout, selected);
    EXPECT_FALSE(missing.has_value());

    state->objects[selected] = {'a'};
    state->fail_remove_identifier = selected;
    const auto failed = protocol::remove_writer(storage, layout, selected);
    EXPECT_FALSE(failed.has_value());
    EXPECT_TRUE(state->objects.contains(selected));

    state->fail_remove_identifier.clear();
    state->fail_writer_list = true;
    const auto listing_failed =
        protocol::remove_writer(storage, layout, selected);
    EXPECT_FALSE(listing_failed.has_value());
    ASSERT_TRUE(listing_failed.error().transport_failure.has_value());
    EXPECT_EQ(listing_failed.error().code,
              protocol::ErrorCode::TransportFailure);
    EXPECT_TRUE(state->objects.contains(selected));
}

TEST(ManualWriterRemovalTest,
     PostRemovalPresenceFailureIsNotReportedAsSuccess) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    const auto selected = layout.writers_prefix + std::string(32, 'a');
    state->objects[selected] = {'a'};
    state->fail_presence_after_removal_identifier = selected;

    const auto removed = protocol::remove_writer(storage, layout, selected);

    ASSERT_FALSE(removed.has_value());
    EXPECT_EQ(removed.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_NE(
        removed.error().detail.find("injected post-removal presence failure"),
        std::string::npos);
    EXPECT_FALSE(state->objects.contains(selected));
}

TEST(MaintenanceProtocolPayloadTest,
     FormatProducesExactExpectedBytesAcrossKindsAndTokens) {
    const std::vector<std::pair<std::string, std::string>> test_cases = {
        {"writer",
         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        {"barrier",
         "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"},
        {"probe",
         "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"},
        {"custom", ""},
        {"", "empty_kind"},
        {"short", "x"},
        {"boundary", std::string(1024, 'z')},
        {"utf8_safe", "token_with_hyphens-and_underscores.123"},
    };

    for (const auto& [kind, token] : test_cases) {
        const auto actual = protocol::testing::format_payload(kind, token);
        const std::string expected_str =
            "kasumi-gc-v1:" + std::string{kind} + ':' + std::string{token};
        const std::vector<std::uint8_t> expected(expected_str.begin(),
                                                 expected_str.end());
        EXPECT_EQ(actual, expected) << "Mismatch for kind: '" << kind
                                    << "' and token: '" << token << "'";
    }
}

TEST(ManualBarrierRemovalTest, RemovesAbandonedBarrierWithVerifiedContent) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace = kasumi::test::make_temp_workspace("barrier-removal-basic");
    const auto payload = protocol::testing::format_payload(
        "barrier", "0123456789abcdef0123456789abcdef");
    state->objects[layout.barrier_identifier] = payload;
    state->objects["unrelated/head"] = {1, 2, 3};

    const auto removed = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));

    ASSERT_TRUE(removed.has_value()) << (removed ? "" : removed.error().detail);
    EXPECT_EQ(removed->outcome, protocol::BarrierRemovalOutcome::Removed);
    EXPECT_EQ(removed->active_writers_count, 0U);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
    EXPECT_TRUE(state->objects.contains("unrelated/head"));
}

TEST(ManualBarrierRemovalTest, BarrierAbsentReturnsAlreadyAbsentWithoutDelete) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("barrier-removal-absent");

    const auto result = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));

    ASSERT_TRUE(result.has_value()) << (result ? "" : result.error().detail);
    EXPECT_EQ(result->outcome, protocol::BarrierRemovalOutcome::AlreadyAbsent);
    EXPECT_EQ(result->active_writers_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST(ManualBarrierRemovalTest, RejectsMalformedOrNonCanonicalBarrierTokens) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("barrier-removal-malformed");

    const std::vector<std::string> invalid_payloads = {
        // Invalid prefixes
        "corrupt",
        "kasumi-gc-v1:barrier",
        "kasumi-gc-v1:barrier;",
        "kasumi-gc-v1:writer:0123456789abcdef0123456789abcdef",
        "kasumi-gc-v2:barrier:0123456789abcdef0123456789abcdef",
        // Non-canonical uppercase hex
        "kasumi-gc-v1:barrier:0123456789ABCDEF0123456789abcdef",
        "kasumi-gc-v1:barrier:0123456789abcdef0123456789ABCDEF",
        // Non-hex characters
        "kasumi-gc-v1:barrier:0123456789abcdef0123456789abcdeg",
        "kasumi-gc-v1:barrier:0123456789abcdef 123456789abcdef",
        "kasumi-gc-v1:barrier:0123456789abcdef-0123456789abcde",
        // Invalid lengths (must be strictly 32 canonical hex chars)
        "kasumi-gc-v1:barrier:0123456789abcdef0123456789abcde",   // 31
        "kasumi-gc-v1:barrier:0123456789abcdef0123456789abcdef0", // 33
        "kasumi-gc-v1:barrier:",                                  // 0
        "kasumi-gc-v1:barrier:"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
        "ef", // 64
    };

    for (const auto& invalid_str : invalid_payloads) {
        state->objects[layout.barrier_identifier] =
            std::vector<std::uint8_t>(invalid_str.begin(), invalid_str.end());
        const auto result = protocol::remove_barrier(
            storage, layout, kasumi::test::workspace_root(workspace));
        ASSERT_FALSE(result.has_value())
            << "Expected failure for payload: " << invalid_str;
        EXPECT_EQ(result.error().code,
                  protocol::ErrorCode::InvalidControlObject);
        EXPECT_EQ(result.error().stage,
                  protocol::BarrierRemovalStage::ValidatingPayload);
        EXPECT_EQ(result.error().mutation_state,
                  protocol::BarrierRemovalMutationState::NotAttempted);
        EXPECT_EQ(state->remove_count, 0U);
    }
}

TEST(ManualBarrierRemovalTest,
     InitialGetFailurePreservesOriginalErrorAndExecutesZeroDeletes) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace = kasumi::test::make_temp_workspace("barrier-get-fail");
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");

    state->fail_get_identifier = layout.barrier_identifier;

    const auto result = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(result.error().stage,
              protocol::BarrierRemovalStage::DownloadingPayload);
    EXPECT_EQ(result.error().mutation_state,
              protocol::BarrierRemovalMutationState::NotAttempted);
    EXPECT_TRUE(result.error().transport_failure.has_value());
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
}

TEST(ManualBarrierRemovalTest, ActiveWritersQueryFailureAbortsWithZeroDeletes) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace = kasumi::test::make_temp_workspace("barrier-writers-fail");
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");

    state->fail_writer_list = true;

    const auto result = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().stage,
              protocol::BarrierRemovalStage::CheckingWriters);
    EXPECT_EQ(result.error().mutation_state,
              protocol::BarrierRemovalMutationState::NotAttempted);
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
}

TEST(ManualBarrierRemovalTest, RemotePhysicalHashFailureAbortsWithZeroDeletes) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace = kasumi::test::make_temp_workspace("barrier-hash-fail");
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");

    state->physical_hash_supported = true;
    state->physical_hash_failure = kasumi::transport::ErrorCode::Io;

    const auto result = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(result.error().stage,
              protocol::BarrierRemovalStage::VerifyingPhysicalIdentity);
    EXPECT_EQ(result.error().mutation_state,
              protocol::BarrierRemovalMutationState::NotAttempted);
    EXPECT_TRUE(result.error().transport_failure.has_value());
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
}

TEST(ManualBarrierRemovalTest, FallbackGetFailureAbortsWithZeroDeletes) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("barrier-fallback-get-fail");
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");

    // Physical hash unsupported triggers GET readback fallback
    state->physical_hash_supported = false;
    int get_invocations = 0;
    state->on_operation =
        [&](FakeState& s, std::string_view op, std::string_view id) {
            if (op == "get" && id == layout.barrier_identifier) {
                ++get_invocations;
                if (get_invocations == 2) {
                    // Fail the second GET during fallback identity verification
                    s.fail_get_identifier = layout.barrier_identifier;
                }
            }
        };

    const auto result = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().stage,
              protocol::BarrierRemovalStage::VerifyingPhysicalIdentity);
    EXPECT_EQ(result.error().mutation_state,
              protocol::BarrierRemovalMutationState::NotAttempted);
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
}

TEST(ManualBarrierRemovalTest,
     BarrierDisappearsDuringInspectionAbortsWithoutDelete) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace = kasumi::test::make_temp_workspace("barrier-disappears");
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");

    state->disappear_on_get = layout.barrier_identifier;

    const auto result = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, protocol::ErrorCode::VerificationFailure);
    EXPECT_NE(result.error().detail.find("disappeared before inspection"),
              std::string::npos);
    EXPECT_EQ(result.error().stage,
              protocol::BarrierRemovalStage::DownloadingPayload);
    EXPECT_EQ(result.error().mutation_state,
              protocol::BarrierRemovalMutationState::NotAttempted);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST(ManualBarrierRemovalTest,
     BarrierReplacedBeforeRemovalAbortsWithoutDeletingReplacement) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("barrier-removal-replaced");
    const auto original_payload = protocol::testing::format_payload(
        "barrier", "0123456789abcdef0123456789abcdef");
    const auto replaced_payload = protocol::testing::format_payload(
        "barrier", "fedcba9876543210fedcba9876543210");
    state->objects[layout.barrier_identifier] = original_payload;

    // Simulate replacement right after initial GET (during writer listing)
    const auto writers_dir =
        layout.writers_prefix.substr(0, layout.writers_prefix.size() - 1);
    state->on_operation =
        [&](FakeState& s, std::string_view op, std::string_view id) {
            if (op == "after_prefix_list" && id == writers_dir) {
                s.objects[layout.barrier_identifier] = replaced_payload;
            }
        };

    const auto result = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, protocol::ErrorCode::VerificationFailure);
    EXPECT_EQ(result.error().stage,
              protocol::BarrierRemovalStage::VerifyingPhysicalIdentity);
    EXPECT_EQ(result.error().mutation_state,
              protocol::BarrierRemovalMutationState::NotAttempted);
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
    EXPECT_EQ(state->objects[layout.barrier_identifier], replaced_payload);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST(ManualBarrierRemovalTest,
     InterleavingSubstitutionAfterRevalidationDemonstratesResidualToctou) {
    // Section 7 Requirement: Controlled test demonstrating residual TOCTOU
    // limit when storage backend lacks distributed CAS.
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace = kasumi::test::make_temp_workspace("barrier-toctou");
    const auto original_payload = protocol::testing::format_payload(
        "barrier", "0123456789abcdef0123456789abcdef");
    const auto concurrent_payload = protocol::testing::format_payload(
        "barrier", "9999999999abcdef0123456789abcdef");
    state->objects[layout.barrier_identifier] = original_payload;

    // Simulate a concurrent process replacing the barrier *after* revalidation
    // passed, right at the moment remove is invoked.
    state->on_operation =
        [&](FakeState& s, std::string_view op, std::string_view id) {
            if (op == "before_remove" && id == layout.barrier_identifier) {
                // Concurrent write happens right before DELETE executes on
                // remote storage
                s.objects[layout.barrier_identifier] = concurrent_payload;
            }
        };

    // Because transport::remove has no CAS condition, it deletes whatever is at
    // that key.
    const auto result = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));

    // Post-removal presence confirms absence because remove deleted the
    // replaced object.
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->outcome, protocol::BarrierRemovalOutcome::Removed);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST(ManualBarrierRemovalTest, HandlesPhysicalHashAndGetFallbackVerification) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("barrier-removal-hash-modes");
    const auto payload = protocol::testing::format_payload(
        "barrier", "0123456789abcdef0123456789abcdef");

    // Case 1: Physical hash mismatch
    state->objects[layout.barrier_identifier] = payload;
    state->physical_hash_supported = true;
    state->physical_hash_mismatch = true;
    auto mismatch = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(mismatch.has_value());
    EXPECT_EQ(mismatch.error().code, protocol::ErrorCode::VerificationFailure);
    EXPECT_EQ(mismatch.error().stage,
              protocol::BarrierRemovalStage::VerifyingPhysicalIdentity);
    EXPECT_EQ(mismatch.error().mutation_state,
              protocol::BarrierRemovalMutationState::NotAttempted);
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
    EXPECT_EQ(state->remove_count, 0U);

    // Case 2: Physical hash unsupported -> GET fallback verification succeeds
    state->physical_hash_supported = false;
    state->physical_hash_mismatch = false;
    auto fallback = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(fallback.has_value())
        << (fallback ? "" : fallback.error().detail);
    EXPECT_EQ(fallback->outcome, protocol::BarrierRemovalOutcome::Removed);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST(ManualBarrierRemovalTest, CoexistenceWithActiveWritersDoesNotDeadlock) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("barrier-coexist-writers");
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");

    const auto writer1 = layout.writers_prefix + std::string(32, 'a');
    const auto writer2 = layout.writers_prefix + std::string(32, 'b');
    state->objects[writer1] = {'1'};
    state->objects[writer2] = {'2'};

    const auto result = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));

    ASSERT_TRUE(result.has_value()) << (result ? "" : result.error().detail);
    EXPECT_EQ(result->outcome, protocol::BarrierRemovalOutcome::Removed);
    EXPECT_EQ(result->active_writers_count, 2U);
    // Barrier is deleted, but writers remain intact
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
    EXPECT_TRUE(state->objects.contains(writer1));
    EXPECT_TRUE(state->objects.contains(writer2));
}

TEST(ManualBarrierRemovalTest, DeleteErrorCategoryDoesNotProveNoMutation) {
    using kasumi::transport::ErrorCode;
    for (const auto code : {ErrorCode::PermissionDenied,
                            ErrorCode::ProtocolFailure,
                            ErrorCode::Unknown,
                            ErrorCode::Timeout}) {
        SCOPED_TRACE(kasumi::transport::error_code_name(code));
        FakeState* state = nullptr;
        auto storage = make_fake_transport(state);
        const auto layout = history::derive_remote_layout(test_key());
        auto workspace =
            kasumi::test::make_temp_workspace("barrier-delete-error-state");
        state->objects[layout.barrier_identifier] =
            protocol::testing::format_payload(
                "barrier", "0123456789abcdef0123456789abcdef");
        state->remove_then_fail_identifier = layout.barrier_identifier;
        state->fail_remove_code = code;
        state->remove_failure_native_code = 10054;

        const auto result = protocol::remove_barrier(
            storage, layout, kasumi::test::workspace_root(workspace));

        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().stage,
                  protocol::BarrierRemovalStage::Removing);
        EXPECT_EQ(result.error().mutation_state,
                  protocol::BarrierRemovalMutationState::Uncertain);
        ASSERT_TRUE(result.error().transport_failure.has_value());
        EXPECT_EQ(result.error().transport_failure->code, code);
        EXPECT_EQ(result.error().transport_failure->native_code, 10054);
        EXPECT_EQ(state->remove_count, 1U);
        EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
    }
}

TEST(ManualBarrierRemovalTest,
     AlreadyAbsentDeleteStillRequiresAbsenceConfirmation) {
    for (const bool fail_confirmation : {false, true}) {
        SCOPED_TRACE(fail_confirmation);
        FakeState* state = nullptr;
        auto storage = make_fake_transport(state);
        const auto layout = history::derive_remote_layout(test_key());
        auto workspace =
            kasumi::test::make_temp_workspace("barrier-already-absent-delete");
        state->objects[layout.barrier_identifier] =
            protocol::testing::format_payload(
                "barrier", "0123456789abcdef0123456789abcdef");
        state->on_operation =
            [&](FakeState& current, std::string_view op, std::string_view id) {
                if (op == "before_remove" && id == layout.barrier_identifier) {
                    current.objects.erase(layout.barrier_identifier);
                }
            };
        if (fail_confirmation) {
            state->fail_presence_after_removal_identifier =
                layout.barrier_identifier;
        }
        const auto presence_before = state->presence_count;

        const auto result = protocol::remove_barrier(
            storage, layout, kasumi::test::workspace_root(workspace));

        EXPECT_EQ(state->remove_count, 1U);
        EXPECT_EQ(state->presence_count - presence_before, 2U);
        if (fail_confirmation) {
            ASSERT_FALSE(result.has_value());
            EXPECT_EQ(result.error().stage,
                      protocol::BarrierRemovalStage::ConfirmingAbsence);
            EXPECT_EQ(result.error().mutation_state,
                      protocol::BarrierRemovalMutationState::Uncertain);
        } else {
            ASSERT_TRUE(result.has_value()) << result.error().detail;
            EXPECT_EQ(result->outcome,
                      protocol::BarrierRemovalOutcome::AlreadyAbsent);
        }
    }
}

TEST(ManualBarrierRemovalTest, TransportErrorsAndAmbiguousDeleteHandling) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("barrier-transport-errors");
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");

    // 1. Initial presence error
    state->fail_barrier_presence = true;
    auto presence_failed = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(presence_failed.has_value());
    EXPECT_EQ(presence_failed.error().code,
              protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(presence_failed.error().stage,
              protocol::BarrierRemovalStage::CheckingPresence);
    EXPECT_EQ(presence_failed.error().mutation_state,
              protocol::BarrierRemovalMutationState::NotAttempted);
    EXPECT_EQ(state->remove_count, 0U);
    state->fail_barrier_presence = false;

    // 2. The error category alone does not prove that DELETE had no effect.
    state->fail_remove_identifier = layout.barrier_identifier;
    state->fail_remove_code = kasumi::transport::ErrorCode::PermissionDenied;
    state->remove_failure_native_code = 400;
    auto delete_failed = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(delete_failed.has_value());
    EXPECT_EQ(delete_failed.error().code,
              protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(delete_failed.error().stage,
              protocol::BarrierRemovalStage::Removing);
    EXPECT_EQ(delete_failed.error().mutation_state,
              protocol::BarrierRemovalMutationState::Uncertain);
    ASSERT_TRUE(delete_failed.error().transport_failure.has_value());
    EXPECT_EQ(delete_failed.error().transport_failure->native_code, 400);
    state->fail_remove_identifier.clear();
    state->fail_remove_code.reset();

    // 3. Ambiguous DELETE error (e.g. Timeout / Io)
    state->fail_remove_identifier = layout.barrier_identifier;
    state->fail_remove_code = kasumi::transport::ErrorCode::Timeout;
    state->remove_failure_native_code = 10060;
    auto ambiguous_failed = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(ambiguous_failed.has_value());
    EXPECT_EQ(ambiguous_failed.error().code,
              protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(ambiguous_failed.error().stage,
              protocol::BarrierRemovalStage::Removing);
    EXPECT_EQ(ambiguous_failed.error().mutation_state,
              protocol::BarrierRemovalMutationState::Uncertain);
    ASSERT_TRUE(ambiguous_failed.error().transport_failure.has_value());
    EXPECT_EQ(ambiguous_failed.error().transport_failure->code,
              kasumi::transport::ErrorCode::Timeout);
    EXPECT_EQ(ambiguous_failed.error().transport_failure->native_code, 10060);
    state->fail_remove_identifier.clear();
    state->fail_remove_code.reset();

    // 4. Post-removal presence check failure
    state->fail_presence_after_removal_identifier = layout.barrier_identifier;
    auto post_presence_failed = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(post_presence_failed.has_value());
    EXPECT_EQ(post_presence_failed.error().code,
              protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(post_presence_failed.error().stage,
              protocol::BarrierRemovalStage::ConfirmingAbsence);
    EXPECT_EQ(post_presence_failed.error().mutation_state,
              protocol::BarrierRemovalMutationState::Uncertain);
    EXPECT_NE(
        post_presence_failed.error().detail.find(
            "could not confirm maintenance barrier absence after removal"),
        std::string::npos);
    EXPECT_FALSE(post_presence_failed.error().detail.starts_with(
        "injected post-removal presence failure"));
}

TEST(ManualBarrierRemovalTest,
     PostRemovalPresenceStillIndicatesBarrierReportsUncertain) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("barrier-presence-remains");
    const auto payload = protocol::testing::format_payload(
        "barrier", "0123456789abcdef0123456789abcdef");
    state->objects[layout.barrier_identifier] = payload;

    // Hook: DELETE succeeds, but when presence check runs right after, barrier
    // is still present
    state->on_operation =
        [&](FakeState& s, std::string_view op, std::string_view id) {
            if (op == "after_remove" && id == layout.barrier_identifier) {
                // Re-insert barrier immediately to simulate persistent presence
                s.objects[layout.barrier_identifier] = payload;
            }
        };

    const auto result = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, protocol::ErrorCode::VerificationFailure);
    EXPECT_NE(result.error().detail.find(
                  "maintenance barrier remains present after removal"),
              std::string::npos);
    EXPECT_EQ(result.error().stage,
              protocol::BarrierRemovalStage::ConfirmingAbsence);
    EXPECT_EQ(result.error().mutation_state,
              protocol::BarrierRemovalMutationState::Uncertain);
}

TEST(ManualBarrierRemovalTest,
     ReexecutionAfterConfirmedRemovalReturnsAlreadyAbsentWithoutDelete) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace = kasumi::test::make_temp_workspace("barrier-reexecution");
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");

    // First execution: removes barrier
    const auto first = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->outcome, protocol::BarrierRemovalOutcome::Removed);
    EXPECT_EQ(state->remove_count, 1U);

    // Second execution: barrier is already gone
    const auto second = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->outcome, protocol::BarrierRemovalOutcome::AlreadyAbsent);
    EXPECT_EQ(state->remove_count, 1U); // No second delete call
}

TEST(ManualBarrierRemovalTest,
     ReexecutionAfterUncertainObservesFreshStateWithoutReusingDecision) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("barrier-reexecution-uncertain");
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");

    // First attempt fails ambiguously
    state->fail_remove_identifier = layout.barrier_identifier;
    state->fail_remove_code = kasumi::transport::ErrorCode::Timeout;
    const auto first = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(first.has_value());
    EXPECT_EQ(first.error().mutation_state,
              protocol::BarrierRemovalMutationState::Uncertain);

    // Backend recovered; second attempt observes fresh state and completes
    // removal
    state->fail_remove_identifier.clear();
    state->fail_remove_code.reset();
    const auto second = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->outcome, protocol::BarrierRemovalOutcome::Removed);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST(ManualBarrierRemovalTest,
     RecreatedBarrierAfterSuccessfulRemovalIsNotDeleted) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace = kasumi::test::make_temp_workspace("barrier-recreated");
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");

    // Remove original barrier
    const auto removed = protocol::remove_barrier(
        storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(removed.has_value());
    EXPECT_EQ(state->remove_count, 1U);

    // Later, a new GC execution creates a fresh barrier with a new token
    const auto new_payload = protocol::testing::format_payload(
        "barrier", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    state->objects[layout.barrier_identifier] = new_payload;

    // No automatic background task or implicit cleanup removes this new barrier
    EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
    EXPECT_EQ(state->remove_count, 1U);
}

TEST(MaintenanceProtocolV024Test,
     MultiBarrierSettleConflictDeletesOnlyOwnBarrierAndPreservesPeer) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->physical_hash_supported = true;
    state->control_read_batch_supported = true;
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace = kasumi::test::make_temp_workspace("multi-barrier-settle");

    const std::string peer_token = "ffffffffffffffffffffffffffffffff";
    const std::string peer_id = layout.barriers_prefix + peer_token;
    bool injected = false;
    state->on_operation =
        [&](FakeState& s, std::string_view op, std::string_view id) {
            if (!injected && op == "after_hash" &&
                id.starts_with(layout.barriers_prefix)) {
                injected = true;
                s.objects[peer_id] =
                    protocol::testing::format_payload("barrier", peer_token);
            }
        };

    const auto t0 = std::chrono::steady_clock::now();
    const auto barrier = protocol::establish_barrier(
        storage,
        layout,
        kasumi::test::workspace_root(workspace),
        protocol::BarrierOptions{.settle_delay =
                                     std::chrono::milliseconds{30}});
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    ASSERT_FALSE(barrier.has_value());
    EXPECT_EQ(barrier.error().code, protocol::ErrorCode::Blocked);
    EXPECT_GE(elapsed, std::chrono::milliseconds{20});
    EXPECT_TRUE(state->objects.contains(peer_id));
    const auto remaining = protocol::active_barriers(storage, layout);
    ASSERT_TRUE(remaining.has_value()) << remaining.error().detail;
    EXPECT_EQ(*remaining, std::vector<std::string>{peer_id});
}

TEST(MaintenanceProtocolV024Test,
     LegacySingleBarrierBlocksWriterAndMultiBarrierAndNeverAutoExpires) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("legacy-barrier-and-no-ttl");
    const auto root = kasumi::test::workspace_root(workspace);

    // 1. Legacy v0.23.x barrier blocks both writer registration and new GC
    // barriers.
    state->objects[layout.barrier_identifier] =
        protocol::testing::format_payload("barrier",
                                          "0123456789abcdef0123456789abcdef");
    const auto writer_blocked =
        protocol::register_writer(storage, layout, root);
    ASSERT_FALSE(writer_blocked.has_value());
    EXPECT_EQ(writer_blocked.error().code, protocol::ErrorCode::Blocked);

    const auto gc_blocked = protocol::establish_barrier(storage, layout, root);
    ASSERT_FALSE(gc_blocked.has_value());
    EXPECT_EQ(gc_blocked.error().code, protocol::ErrorCode::Blocked);
    state->objects.erase(layout.barrier_identifier);

    // 2. Old marker timestamps (e.g. Unix epoch + 1s) remain diagnostic-only
    // and never auto-expire.
    const protocol::MarkerMetadata ancient_meta{
        .machine_name = "ancient\nworkstation",
        .pid = 4242,
        .started_at_unix = 1,
    };
    auto writer =
        protocol::register_writer(storage, layout, root, ancient_meta);
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;

    const auto parsed = protocol::read_marker_metadata(
        storage, writer->identifier, "writer", writer->token, root);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->machine_name, "ancient workstation");
    EXPECT_EQ(parsed->pid, 4242U);
    EXPECT_EQ(parsed->started_at_unix, 1);

    const auto blocked_by_old_writer =
        protocol::establish_barrier(storage, layout, root);
    ASSERT_FALSE(blocked_by_old_writer.has_value());
    EXPECT_EQ(blocked_by_old_writer.error().code, protocol::ErrorCode::Blocked);
    EXPECT_TRUE(state->objects.contains(writer->identifier));
    ASSERT_TRUE(protocol::release_registration(*writer));
}

TEST(MaintenanceProtocolV024Test,
     MultiBarrierManualRemovalSupportsAutoSingleAmbiguousRejectAndTargetedId) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto layout = history::derive_remote_layout(test_key());
    auto workspace =
        kasumi::test::make_temp_workspace("multi-barrier-manual-remove");
    const auto root = kasumi::test::workspace_root(workspace);

    const std::string token1 = "11111111111111111111111111111111";
    const std::string token2 = "22222222222222222222222222222222";
    const std::string id1 = layout.barriers_prefix + token1;
    const std::string id2 = layout.barriers_prefix + token2;
    const protocol::MarkerMetadata meta1{
        .machine_name = "host-one", .pid = 101, .started_at_unix = 1700000100};
    const protocol::MarkerMetadata meta2{
        .machine_name = "host-two", .pid = 202, .started_at_unix = 1700000200};
    state->objects[id1] =
        protocol::testing::format_payload("barrier", token1, meta1);
    state->objects[id2] =
        protocol::testing::format_payload("barrier", token2, meta2);

    // 1. Multiple active barriers require an explicit identifier/token.
    const auto ambiguous = protocol::remove_barrier(storage, layout, root);
    ASSERT_FALSE(ambiguous.has_value());
    EXPECT_EQ(ambiguous.error().stage,
              protocol::BarrierRemovalStage::CheckingPresence);
    EXPECT_EQ(ambiguous.error().mutation_state,
              protocol::BarrierRemovalMutationState::NotAttempted);
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_TRUE(state->objects.contains(id1));
    EXPECT_TRUE(state->objects.contains(id2));

    // 2. Targeted removal by bare 32-hex token deletes only barrier 1.
    const auto first = protocol::remove_barrier(storage, layout, root, token1);
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    EXPECT_EQ(first->outcome, protocol::BarrierRemovalOutcome::Removed);
    EXPECT_EQ(first->remaining_barriers_count, 1U);
    EXPECT_EQ(first->barrier_identifier, id1);
    EXPECT_FALSE(state->objects.contains(id1));
    EXPECT_TRUE(state->objects.contains(id2));

    // 3. Auto-removal succeeds once a single barrier remains.
    const auto second = protocol::remove_barrier(storage, layout, root);
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_EQ(second->outcome, protocol::BarrierRemovalOutcome::Removed);
    EXPECT_EQ(second->remaining_barriers_count, 0U);
    EXPECT_EQ(second->barrier_identifier, id2);
    EXPECT_FALSE(state->objects.contains(id2));
}

TEST(ManualWriterRemovalTest,
     RemoveWritersRemovesMultipleInBatchReportsAbsentAndChecksBarriers) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto layout = history::derive_remote_layout(test_key());
    const std::string w1 = layout.writers_prefix + std::string(32, '1');
    const std::string w2 = layout.writers_prefix + std::string(32, '2');
    const std::string missing_w = layout.writers_prefix + std::string(32, '3');
    const std::string kept = layout.writers_prefix + std::string(32, '4');

    state->objects[w1] = {'a'};
    state->objects[w2] = {'b'};
    state->objects[kept] = {'k'};

    // Blocked when a barrier is present.
    const std::string barrier_id =
        layout.barriers_prefix + std::string(32, 'f');
    state->objects[barrier_id] = {'x'};
    const std::vector<std::string> blocked_targets{w1};
    const auto blocked =
        protocol::remove_writers(storage, layout, blocked_targets);
    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(blocked.error().code, protocol::ErrorCode::Blocked);
    state->objects.erase(barrier_id);

    // Invalid IDs fail before mutating anything.
    const std::vector<std::string> invalid_targets{w1, "bad/id"};
    const auto invalid =
        protocol::remove_writers(storage, layout, invalid_targets);
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code, protocol::ErrorCode::InvalidInput);
    EXPECT_TRUE(state->objects.contains(w1));

    // Batch removal deduplicates, removes w1 & w2, reports missing_w as
    // already_absent, and leaves unrelated markers untouched.
    std::vector<std::pair<std::size_t, std::size_t>> steps;
    const std::vector<std::string> targets{w1, w2, w1, missing_w};
    const auto batch = protocol::remove_writers(
        storage,
        layout,
        targets,
        [&](std::size_t done, std::size_t total, std::string_view) {
            steps.emplace_back(done, total);
        });
    ASSERT_TRUE(batch.has_value()) << batch.error().detail;
    EXPECT_EQ(batch->removed, (std::vector<std::string>{w1, w2}));
    EXPECT_EQ(batch->already_absent, (std::vector<std::string>{missing_w}));
    EXPECT_FALSE(state->objects.contains(w1));
    EXPECT_FALSE(state->objects.contains(w2));
    EXPECT_TRUE(state->objects.contains(kept));
    ASSERT_FALSE(steps.empty());
    EXPECT_EQ(steps.back(), (std::pair<std::size_t, std::size_t>{3U, 3U}));
}

} // namespace
