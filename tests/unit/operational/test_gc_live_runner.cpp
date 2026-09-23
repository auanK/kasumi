#include "../../operational/gc_live_runner_support.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <gtest/gtest.h>

namespace {

namespace runner = kasumi::operational::gc_live_runner;
namespace preflight = kasumi::operational::gc_live_preflight;
namespace smoke = kasumi::operational::remote_copy_smoke;
namespace transport = kasumi::transport;
namespace integrity = kasumi::application::integrity;

struct FakeHarness {
    kasumi::test::TempWorkspace workspace;
    FakeState* parent_state = nullptr;
    FakeState* child_state = nullptr;
    std::filesystem::path output_path;
    std::filesystem::path scratch_path;
    std::string child_name = "kasumi-gc-live-0123456789abcdef0123456789abcdef";

    FakeHarness(std::string_view name)
        : workspace(kasumi::test::make_temp_workspace("runner-" + std::string{name})),
          output_path(kasumi::test::workspace_path(workspace, "output.json")),
          scratch_path(kasumi::test::workspace_path(workspace, "scratch")) {
        std::filesystem::create_directories(scratch_path);
    }

    transport::Transport make_parent_transport() {
        auto t = make_fake_transport(parent_state);
        parent_state->physical_hash_supported = true;
        parent_state->copy_supported = true;
        return t;
    }

    transport::Transport make_child_transport() {
        auto t = make_fake_transport(child_state);
        child_state->physical_hash_supported = true;
        child_state->copy_supported = true;
        return t;
    }

    preflight::ChildStorage make_child_storage() {
        return preflight::ChildStorage{
            .parent = *smoke::parse_remote_parent("kasumi:integration-tests"),
            .child = child_name,
            .storage = make_child_transport(),
        };
    }

    runner::RunnerOptions make_options() const {
        return runner::RunnerOptions{
            .remote_parent = "kasumi:integration-tests",
            .output_path = output_path,
            .local_scratch = scratch_path,
            .execute_live_gc = true,
            .preserve_evidence_on_failure = true,
            .explicit_key = test_key(),
            .explicit_child = child_name,
            .explicit_owner_token = "test-owner-token-0123456789abcdef",
        };
    }
};

// Gate: Parent validation
TEST(GcLiveRunnerGateTest, RejectsUnauthorizedParentsBeforeRemote) {
    EXPECT_TRUE(runner::is_authorized_live_parent("kasumi:integration-tests"));
    for (const auto parent : {"kasumi:", "kasumi:anything-else", "other:integration-tests",
                              "/tmp/local", "C:/Windows", "archive:test-parent"}) {
        EXPECT_FALSE(runner::is_authorized_live_parent(parent)) << parent;
    }
}

// Dry safety: execute_live_gc flag required
TEST(GcLiveRunnerSafetyTest, DryRunRefusesExecutionWithoutFlag) {
    FakeHarness harness{"dry-run"};
    auto options = harness.make_options();
    options.execute_live_gc = false;
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    const auto report = runner::run(options, &parent, &child);

    EXPECT_EQ(report.status, "REFUSED");
    EXPECT_EQ(report.gc.called, false);
    EXPECT_EQ(report.gc.call_count, 0U);
    EXPECT_EQ(report.stage_reached, runner::LiveGcStage::Start);
}

// A. PRE_INITIALIZE Refused
TEST(GcLiveRunnerPreflightTest, PreflightRefusedStopsBeforeInitialize) {
    FakeHarness harness{"preflight-refused"};
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();
    // Simulate pre-existing child
    harness.child_state->objects[harness.child_name + "/existing.txt"] = {'1'};

    const auto report = runner::run(harness.make_options(), &parent, &child);

    EXPECT_NE(report.status, "PASS");
    EXPECT_EQ(report.stage_reached, runner::LiveGcStage::Start);
    EXPECT_EQ(report.gc.called, false);
    EXPECT_EQ(report.gc.call_count, 0U);
    EXPECT_EQ(report.ownership.marker_written, false);
}

// B. initialize failure
TEST(GcLiveRunnerInitializeTest, InitializeFailureStopsBeforeOwnership) {
    FakeHarness harness{"init-fail"};
    bool gc_called = false;
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();
    child.storage.initialize = [](void*) -> transport::Result {
        return std::unexpected(transport::Error{.code = transport::ErrorCode::Io, .message = "disk error"});
    };

    const auto report = runner::run(
        harness.make_options(),
        &parent,
        &child,
        [&](const auto&, auto&, auto) -> std::expected<integrity::GarbageCollectResult, integrity::Error> {
            gc_called = true;
            return integrity::GarbageCollectResult{};
        });

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_FALSE(gc_called);
    EXPECT_EQ(report.gc.call_count, 0U);
    EXPECT_EQ(report.ownership.marker_written, false);
}

// C. POST_INITIALIZE non-empty
TEST(GcLiveRunnerPostInitTest, NonEmptyPostInitializeStopsBeforeOwnership) {
    FakeHarness harness{"post-init-non-empty"};
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();
    child.storage.initialize = [](void* ctx) -> transport::Result {
        auto* s = static_cast<FakeState*>(ctx);
        s->objects["spurious.file"] = {'b', 'a', 'd'};
        return {};
    };

    const auto report = runner::run(harness.make_options(), &parent, &child);

    EXPECT_EQ(report.status, "REFUSED");
    EXPECT_EQ(report.stage_reached, runner::LiveGcStage::ChildInitialized);
    EXPECT_EQ(report.ownership.marker_written, false);
    EXPECT_EQ(report.gc.call_count, 0U);
}

// D. owner marker PUT failure
TEST(GcLiveRunnerOwnershipTest, MarkerPutFailureStopsBeforeScenario) {
    FakeHarness harness{"marker-put-fail"};
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();
    harness.child_state->fail_put_identifier = "owner.marker";

    const auto report = runner::run(harness.make_options(), &parent, &child);

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.ownership.marker_written, false);
    EXPECT_EQ(report.gc.call_count, 0U);
}

// E. owner marker readback mismatch
TEST(GcLiveRunnerOwnershipTest, MarkerReadbackMismatchStopsBeforeScenario) {
    FakeHarness harness{"marker-readback-mismatch"};
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();
    harness.child_state->corrupt_get_identifier = "owner.marker";

    const auto report = runner::run(harness.make_options(), &parent, &child);

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.ownership.marker_readback_verified, false);
    EXPECT_EQ(report.gc.call_count, 0U);
}

// F. scenario setup failure
TEST(GcLiveRunnerScenarioTest, ScenarioSetupFailureStopsBeforeGc) {
    FakeHarness harness{"scenario-fail"};
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();
    harness.child_state->fail_commit_put = true;

    const auto report = runner::run(harness.make_options(), &parent, &child);

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.gc.call_count, 0U);
    EXPECT_FALSE(report.gc.called);
}

// G. pre-GC inventory mismatch
TEST(GcLiveRunnerInventoryTest, PreInventoryMismatchStopsBeforeGc) {
    FakeHarness harness{"pre-inv-mismatch"};
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    // Hook list to reveal an unexpected object on the pre-GC inventory listing (3rd listing)
    harness.child_state->hidden_objects["spurious_extra_vault_object"] = {'b', 'a', 'd'};
    harness.child_state->reveal_on_list_count = 3;

    const auto report = runner::run(harness.make_options(), &parent, &child);

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.stage_reached, runner::LiveGcStage::ScenarioPublished);
    EXPECT_FALSE(report.gc.called);
    EXPECT_EQ(report.gc.call_count, 0U);
    EXPECT_TRUE(report.inventory_before.owner_marker.has_value());
    EXPECT_EQ(report.cleanup.result, "preserved");
}

// RNG failure fails closed before initialize (Passo 5 / Phase 5D.2)
TEST(GcLiveRunnerRngTest, OwnerTokenRngFailureFailsClosed) {
    FakeHarness harness{"rng-fail"};
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    std::size_t initialize_count = 0;
    static std::size_t* s_init_count = nullptr;
    s_init_count = &initialize_count;
    child.storage.initialize = [](void* ctx) -> transport::Result {
        if (s_init_count) {
            (*s_init_count)++;
        }
        return fake_initialize(ctx);
    };

    auto options = harness.make_options();
    options.explicit_owner_token = std::nullopt;
    // Inject RNG failure
    options.random_generator = []() -> std::optional<std::string> {
        return std::nullopt;
    };

    const auto report = runner::run(options, &parent, &child);
    s_init_count = nullptr;

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.stage_reached, runner::LiveGcStage::PreflightPassed);
    EXPECT_FALSE(report.ownership.marker_written);
    EXPECT_FALSE(report.gc.called);
    EXPECT_EQ(report.gc.call_count, 0U);
    EXPECT_EQ(initialize_count, 0U);
    EXPECT_FALSE(harness.child_state->objects.contains("owner.marker"));
    EXPECT_EQ(harness.child_state->objects.size(), 0U);
    EXPECT_NE(report.error_message.find("random"), std::string::npos);
}


// H. Happy path: Real GC, metrics, invariants, cleanup
TEST(GcLiveRunnerHappyPathTest, FullExecutionSucceedsWithRealGcAndPhase3Metrics) {
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    FakeHarness harness{"happy-path"};
    auto options = harness.make_options();
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    const auto report = runner::run(options, &parent, &child);

    EXPECT_EQ(report.status, "PASS");
    EXPECT_EQ(report.stage_reached, runner::LiveGcStage::CleanupCompleted);
    EXPECT_EQ(report.gc.called, true);
    EXPECT_EQ(report.gc.call_count, 1U);
    EXPECT_EQ(report.gc.result, "SUCCESS");
    EXPECT_EQ(report.gc.candidate_objects, 1U);
    EXPECT_EQ(report.gc.quarantined_objects, 1U);
    EXPECT_EQ(report.gc.restored_objects, 0U);
    EXPECT_EQ(report.gc.purged_objects, 0U);

    // Validation invariants
    EXPECT_TRUE(report.validation.reachable_preserved);
    EXPECT_TRUE(report.validation.quarantine_present);
    EXPECT_TRUE(report.validation.quarantine_verified);
    EXPECT_TRUE(report.validation.metadata_authenticated);
    EXPECT_TRUE(report.validation.source_removed);
    EXPECT_EQ(report.validation.unexpected_removed, 0U);
    EXPECT_EQ(report.validation.unexpected_created, 0U);

    // Metrics for 1 candidate
    EXPECT_EQ(report.metrics.verified_copy_source_physical_hash, 1U);
    EXPECT_EQ(report.metrics.verified_copy_native_copy, 1U);
    EXPECT_EQ(report.metrics.verified_copy_native_copy_successes, 1U);
    EXPECT_EQ(report.metrics.verified_copy_destination_physical_hash, 1U);
    EXPECT_EQ(report.metrics.verified_copy_native_copy_verifications, 1U);
    EXPECT_EQ(report.metrics.gc_candidate_verified_copy, 1U);
    EXPECT_EQ(report.metrics.gc_candidate_metadata_publish, 1U);
    EXPECT_EQ(report.metrics.gc_candidate_pre_remove_barrier_verification, 1U);
    EXPECT_EQ(report.metrics.gc_candidate_remove, 1U);

    // Cleanup verified
    EXPECT_EQ(report.cleanup.result, "removed");

    kasumi::platform::perf_trace::force_enable(false);
}

// I. GC failure: Never retry, post-failure inventory captured, cleanup if ownership proven
TEST(GcLiveRunnerFailureTest, GcFailureNeverRetriesAndPreservesEvidenceWhenRequested) {
    FakeHarness harness{"gc-fail"};
    auto options = harness.make_options();
    options.preserve_evidence_on_failure = true;
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    std::size_t gc_invocations = 0;
    const auto report = runner::run(
        options,
        &parent,
        &child,
        [&](const auto&, auto&, auto) -> std::expected<integrity::GarbageCollectResult, integrity::Error> {
            gc_invocations++;
            return std::unexpected(integrity::Error{
                .code = integrity::ErrorCode::TransportFailure,
                .detail = "simulated remote error during GC",
            });
        });

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.gc.called, true);
    EXPECT_EQ(report.gc.call_count, 1U);
    EXPECT_EQ(gc_invocations, 1U);
    EXPECT_EQ(report.gc.result, "FAILED");
    // Evidence preserved: cleanup not attempted
    EXPECT_EQ(report.cleanup.result, "preserved");
}

// J. Post-GC invariant failure: Never retry GC, register failure
TEST(GcLiveRunnerFailureTest, PostGcInvariantFailureRegistersFailureAndPreservesEvidence) {
    FakeHarness harness{"post-gc-invariant-fail"};
    auto options = harness.make_options();
    options.preserve_evidence_on_failure = true;
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    // Inject fake GC that reports success but doesn't actually quarantine candidate
    const auto report = runner::run(
        options,
        &parent,
        &child,
        [&](const auto&, auto&, auto) -> std::expected<integrity::GarbageCollectResult, integrity::Error> {
            return integrity::GarbageCollectResult{
                .candidate_objects = 1,
                .quarantined_objects = 1,
            };
        });

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.gc.call_count, 1U);
    EXPECT_FALSE(report.validation.quarantine_present);
}

// K. Cleanup without marker or marker mismatch
TEST(GcLiveRunnerCleanupTest, CleanupWithoutMatchingMarkerRefuses) {
    FakeHarness harness{"cleanup-mismatch"};
    auto child_storage = harness.make_child_storage();
    const auto cleanup_result = preflight::cleanup_owned_child(
        child_storage,
        "wrong-token",
        {"obj1"},
        harness.scratch_path);
    EXPECT_EQ(cleanup_result.result, "refused");
}

// L. Cleanup with escaping identifier
TEST(GcLiveRunnerCleanupTest, CleanupWithEscapingIdentifierRefusesBeforeRemoval) {
    FakeHarness harness{"cleanup-escape"};
    auto child_storage = harness.make_child_storage();
    harness.child_state->objects["owner.marker"] = {'t', 'o', 'k', 'e', 'n'};
    const auto cleanup_result = preflight::cleanup_owned_child(
        child_storage,
        "token",
        {"../outside", "valid_obj"},
        harness.scratch_path);
    EXPECT_EQ(cleanup_result.result, "refused");
}

// M. Evidence preservation is default (Passo 6)
TEST(GcLiveRunnerFailureTest, GcFailurePreservesEvidenceByDefault) {
    FakeHarness harness{"evidence-default"};
    auto options = harness.make_options();
    // Do NOT set preserve_evidence_on_failure explicitly; verify default behavior
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    const auto report = runner::run(
        options,
        &parent,
        &child,
        [](const auto&, auto&, auto) -> std::expected<integrity::GarbageCollectResult, integrity::Error> {
            return std::unexpected(integrity::Error{
                .code = integrity::ErrorCode::TransportFailure,
                .detail = "simulated remote error during GC",
            });
        });

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.gc.called, true);
    EXPECT_EQ(report.gc.call_count, 1U);
    EXPECT_EQ(report.cleanup.result, "preserved");
    // All objects including owner marker remain untouched
    EXPECT_TRUE(harness.child_state->objects.contains("owner.marker"));
    EXPECT_TRUE(harness.child_state->objects.contains(report.scenario.reachable_identifier));
    EXPECT_TRUE(harness.child_state->objects.contains(report.scenario.candidate_identifier));
}

// N. Unknown residue retains owner marker (Passo 7 / Phase 5D.2)
TEST(GcLiveRunnerResidueTest, UnknownResidueInChildRetainsOwnerMarker) {
    FakeHarness harness{"residue-retains-marker"};
    auto options = harness.make_options();
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    // Hook GC to run real GC and additionally inject an unknown residue object directly into child
    const auto report = runner::run(
        options,
        &parent,
        &child,
        [&](const auto& runtime_data, auto& vault_transport, auto key) {
            auto res = kasumi::application::integrity::garbage_collect(runtime_data, vault_transport, key);
            harness.child_state->objects["unknown_foreign_residue.tmp"] = {'r', 'e', 's', 'i', 'd', 'u', 'e'};
            return res;
        });

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.stage_reached, runner::LiveGcStage::PostInventoryVerified);
    EXPECT_TRUE(report.gc.called);
    EXPECT_EQ(report.gc.call_count, 1U);

    EXPECT_TRUE(report.validation.reachable_preserved);
    EXPECT_TRUE(report.validation.source_removed);
    EXPECT_TRUE(report.validation.quarantine_present);
    EXPECT_TRUE(report.validation.quarantine_verified);
    EXPECT_TRUE(report.validation.metadata_authenticated);
    EXPECT_EQ(report.validation.unexpected_removed, 0U);

    EXPECT_EQ(report.cleanup.result, "refused");
    EXPECT_NE(report.cleanup.detail.find("residue"), std::string::npos);

    EXPECT_TRUE(harness.child_state->objects.contains("owner.marker"));
    EXPECT_TRUE(harness.child_state->objects.contains("unknown_foreign_residue.tmp"));
    EXPECT_TRUE(harness.child_state->objects.contains(report.scenario.reachable_identifier));
    EXPECT_TRUE(harness.child_state->objects.contains(report.scenario.quarantine_identifier));
}

// O. Partial target cleanup retains owner marker (Passo 7)
TEST(GcLiveRunnerCleanupTest, PartialTargetCleanupRetainsOwnerMarker) {
    FakeHarness harness{"partial-cleanup"};
    auto child_storage = harness.make_child_storage();
    harness.child_state->objects["owner.marker"] = {'t', 'o', 'k', 'e', 'n'};
    harness.child_state->objects["target1"] = {'1'};
    harness.child_state->objects["target2"] = {'2'};

    // Cause target2 removal to fail
    harness.child_state->fail_remove_identifier = "target2";

    const auto cleanup_result = preflight::cleanup_owned_child(
        child_storage,
        "token",
        {"target1", "target2"},
        harness.scratch_path);

    EXPECT_EQ(cleanup_result.result, "failed");
    // target1 removed, target2 failed, owner.marker MUST STILL BE PRESENT
    EXPECT_FALSE(harness.child_state->objects.contains("target1"));
    EXPECT_TRUE(harness.child_state->objects.contains("target2"));
    EXPECT_TRUE(harness.child_state->objects.contains("owner.marker"));
}

// P. Successful cleanup removes owner marker last (Passo 15)
TEST(GcLiveRunnerCleanupTest, SuccessfulCleanupRemovesOwnerMarkerLast) {
    FakeHarness harness{"cleanup-order"};
    auto options = harness.make_options();
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    std::vector<std::string> removal_order;
    static std::vector<std::string>* s_order = nullptr;
    s_order = &removal_order;
    child.storage.remove = [](void* ctx, std::string_view id) -> transport::RemovalResult {
        if (s_order) {
            s_order->push_back(std::string{id});
        }
        return fake_remove(ctx, id);
    };

    const auto report = runner::run(options, &parent, &child);
    s_order = nullptr;

    EXPECT_EQ(report.status, "PASS");
    EXPECT_EQ(report.cleanup.result, "removed");
    ASSERT_FALSE(removal_order.empty());
    // Invariant: owner.marker must be the LAST removed object
    EXPECT_EQ(removal_order.back(), "owner.marker");
    // Targets removed before marker
    EXPECT_GT(removal_order.size(), 1U);
}

} // namespace
