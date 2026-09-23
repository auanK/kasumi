#include "../../operational/gc_live_runner_support.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

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

// RED Test for Passo 3: Native get_batch receives correct context
struct NativeBatchState {
    static constexpr std::uint32_t kMagic = 0x54415453; // "STAT"
    std::uint32_t magic = kMagic;
    std::size_t get_batch_calls = 0;
    bool context_matched = false;
    std::string last_identifier;
};

TEST(VaultTransportAdapterTest, NativeGetBatchReceivesCorrectContext) {
    auto* raw_state = new NativeBatchState{};
    transport::Transport base_transport{
        .state = transport::TransportStateHandle{raw_state, [](void* p) noexcept {
            delete static_cast<NativeBatchState*>(p);
        }},
        .storage = transport::StorageOperations{
            .initialize = [](void* ctx) -> transport::Result {
                auto* s = static_cast<NativeBatchState*>(ctx);
                if (s->magic != NativeBatchState::kMagic) {
                    return std::unexpected(transport::Error{.code = transport::ErrorCode::InvalidContext, .message = "init ctx mismatch"});
                }
                return {};
            },
            .put = [](void*, const std::filesystem::path&, std::string_view) -> transport::Result { return {}; },
            .get = [](void*, std::string_view, const std::filesystem::path&) -> transport::Result { return {}; },
            .get_batch = [](void* ctx, const transport::GetBatch& batch) -> transport::Result {
                auto* s = static_cast<NativeBatchState*>(ctx);
                if (s->magic != NativeBatchState::kMagic) {
                    return std::unexpected(transport::Error{
                        .code = transport::ErrorCode::InvalidContext,
                        .message = "get_batch ctx mismatch: expected NativeBatchState",
                    });
                }
                s->context_matched = true;
                s->get_batch_calls++;
                if (!batch.identifiers.empty()) {
                    s->last_identifier = batch.identifiers.front();
                }
                return {};
            },
            .presence = [](void*, std::string_view) -> transport::PresenceResult { return transport::Presence::Present; },
            .list = [](void*) -> transport::ListingResult { return std::vector<std::string>{}; },
            .remove = [](void*, std::string_view) -> transport::RemovalResult { return transport::Removal::Removed; },
        },
    };

    auto vault_transport = runner::make_vault_transport(base_transport, "owner.marker");

    kasumi::test::TempWorkspace ws(kasumi::test::make_temp_workspace("get-batch-test"));
    transport::GetBatch batch{
        .destination_root = kasumi::test::workspace_path(ws, "dest"),
        .identifiers = {"test_object.bin"},
    };
    std::filesystem::create_directories(batch.destination_root);

    auto result = transport::get_batch(vault_transport, batch);
    EXPECT_TRUE(result.has_value()) << (result ? "" : result.error().message);
    EXPECT_TRUE(raw_state->context_matched);
    EXPECT_EQ(raw_state->get_batch_calls, 1U);
}

// Passo 12: PutBatch delegates and protects owner marker
TEST(VaultTransportAdapterTest, PutBatchDelegatesAndProtectsMarker) {
    auto* raw_state = new NativeBatchState{};
    transport::Transport base_transport{
        .state = transport::TransportStateHandle{raw_state, [](void* p) noexcept {
            delete static_cast<NativeBatchState*>(p);
        }},
        .storage = transport::StorageOperations{
            .initialize = [](void*) -> transport::Result { return {}; },
            .put = [](void*, const std::filesystem::path&, std::string_view) -> transport::Result { return {}; },
            .put_batch = [](void* ctx, const transport::PutBatch& batch) -> transport::Result {
                auto* s = static_cast<NativeBatchState*>(ctx);
                if (s->magic != NativeBatchState::kMagic) {
                    return std::unexpected(transport::Error{.code = transport::ErrorCode::InvalidContext, .message = "put_batch ctx mismatch"});
                }
                s->context_matched = true;
                s->get_batch_calls++;
                if (!batch.identifiers.empty()) {
                    s->last_identifier = batch.identifiers.front();
                }
                return {};
            },
            .get = [](void*, std::string_view, const std::filesystem::path&) -> transport::Result { return {}; },
            .presence = [](void*, std::string_view) -> transport::PresenceResult { return transport::Presence::Present; },
            .list = [](void*) -> transport::ListingResult { return std::vector<std::string>{}; },
            .remove = [](void*, std::string_view) -> transport::RemovalResult { return transport::Removal::Removed; },
        },
    };

    auto vault_transport = runner::make_vault_transport(base_transport, "owner.marker");

    kasumi::test::TempWorkspace ws(kasumi::test::make_temp_workspace("put-batch-test"));
    auto src_dir = kasumi::test::workspace_path(ws, "src");
    std::filesystem::create_directories(src_dir);
    auto file_path = src_dir / "obj1.bin";
    std::ofstream(file_path, std::ios::binary) << "hello";

    transport::PutBatch valid_batch{
        .source_root = src_dir,
        .identifiers = {"obj1.bin"},
        .max_parallel_transfers = 4,
    };
    auto res_valid = transport::put_batch(vault_transport, valid_batch);
    EXPECT_TRUE(res_valid.has_value());
    EXPECT_TRUE(raw_state->context_matched);
    EXPECT_EQ(raw_state->last_identifier, "obj1.bin");

    auto src_marker = kasumi::test::workspace_path(ws, "src_marker");
    std::filesystem::create_directories(src_marker);
    std::ofstream(src_marker / "owner.marker", std::ios::binary) << "marker";
    transport::PutBatch marker_batch{
        .source_root = src_marker,
        .identifiers = {"owner.marker"},
    };
    auto res_marker = transport::put_batch(vault_transport, marker_batch);
    EXPECT_FALSE(res_marker.has_value());
    EXPECT_EQ(res_marker.error().code, transport::ErrorCode::InvalidIdentifier);
}

// Passo 9: Fallback when base get_batch is null
TEST(VaultTransportAdapterTest, GetBatchFallbackWhenBaseNull) {
    auto* raw_state = new NativeBatchState{};
    transport::Transport base_transport{
        .state = transport::TransportStateHandle{raw_state, [](void* p) noexcept {
            delete static_cast<NativeBatchState*>(p);
        }},
        .storage = transport::StorageOperations{
            .initialize = [](void*) -> transport::Result { return {}; },
            .put = [](void*, const std::filesystem::path&, std::string_view) -> transport::Result { return {}; },
            .get = [](void* ctx, std::string_view id, const std::filesystem::path& dest) -> transport::Result {
                auto* s = static_cast<NativeBatchState*>(ctx);
                if (s->magic != NativeBatchState::kMagic) {
                    return std::unexpected(transport::Error{.code = transport::ErrorCode::InvalidContext, .message = "get ctx mismatch"});
                }
                s->context_matched = true;
                s->last_identifier = std::string{id};
                std::filesystem::create_directories(dest.parent_path());
                std::ofstream(dest, std::ios::binary) << "content";
                return {};
            },
            .get_batch = nullptr,
            .presence = [](void*, std::string_view) -> transport::PresenceResult { return transport::Presence::Present; },
            .list = [](void*) -> transport::ListingResult { return std::vector<std::string>{}; },
            .remove = [](void*, std::string_view) -> transport::RemovalResult { return transport::Removal::Removed; },
        },
    };

    auto vault_transport = runner::make_vault_transport(base_transport, "owner.marker");
    EXPECT_EQ(vault_transport.storage.get_batch, nullptr);

    kasumi::test::TempWorkspace ws(kasumi::test::make_temp_workspace("get-batch-fallback"));
    transport::GetBatch batch{
        .destination_root = kasumi::test::workspace_path(ws, "dest"),
        .identifiers = {"fallback_obj.bin"},
    };
    std::filesystem::create_directories(batch.destination_root);

    auto result = transport::get_batch(vault_transport, batch);
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(raw_state->context_matched);
    EXPECT_EQ(raw_state->last_identifier, "fallback_obj.bin");
}

// Passo 11: PhysicalHashBatch delegates and protects owner marker
TEST(VaultTransportAdapterTest, PhysicalHashBatchDelegatesAndProtectsMarker) {
    auto* raw_state = new NativeBatchState{};
    transport::Transport base_transport{
        .state = transport::TransportStateHandle{raw_state, [](void* p) noexcept {
            delete static_cast<NativeBatchState*>(p);
        }},
        .storage = transport::StorageOperations{
            .initialize = [](void*) -> transport::Result { return {}; },
            .put = [](void*, const std::filesystem::path&, std::string_view) -> transport::Result { return {}; },
            .get = [](void*, std::string_view, const std::filesystem::path&) -> transport::Result { return {}; },
            .presence = [](void*, std::string_view) -> transport::PresenceResult { return transport::Presence::Present; },
            .list = [](void*) -> transport::ListingResult { return std::vector<std::string>{}; },
            .physical_hash_batch = [](void* ctx, const transport::PhysicalHashBatchRequest&) -> transport::PhysicalHashBatchResult {
                auto* s = static_cast<NativeBatchState*>(ctx);
                if (s->magic != NativeBatchState::kMagic) {
                    return std::unexpected(transport::Error{.code = transport::ErrorCode::InvalidContext, .message = "hash_batch ctx mismatch"});
                }
                s->context_matched = true;
                return transport::PhysicalHashBatchReport{};
            },
            .remove = [](void*, std::string_view) -> transport::RemovalResult { return transport::Removal::Removed; },
            .physical_hash_batch_min_objects = 2,
        },
    };

    auto vault_transport = runner::make_vault_transport(base_transport, "owner.marker");
    EXPECT_NE(vault_transport.storage.physical_hash_batch, nullptr);
    EXPECT_EQ(vault_transport.storage.physical_hash_batch_min_objects, 2U);

    kasumi::test::TempWorkspace ws(kasumi::test::make_temp_workspace("hash-batch-test"));
    auto scratch = kasumi::test::workspace_path(ws, "scratch");
    std::filesystem::create_directories(scratch);

    transport::PhysicalHashBatchRequest valid_req{
        .scratch_root = scratch,
        .objects = {
            {.identifier = "valid1", .expected_hash = "abc"},
            {.identifier = "valid2", .expected_hash = "def"},
        },
        .algorithm = "sha256",
    };
    auto res_valid = transport::physical_hash_batch(vault_transport, valid_req);
    EXPECT_TRUE(res_valid.has_value());
    EXPECT_TRUE(raw_state->context_matched);

    transport::PhysicalHashBatchRequest marker_req{
        .scratch_root = scratch,
        .objects = {
            {.identifier = "owner.marker", .expected_hash = "abc"},
        },
        .algorithm = "sha256",
    };
    auto res_marker = transport::physical_hash_batch(vault_transport, marker_req);
    EXPECT_FALSE(res_marker.has_value());
    EXPECT_EQ(res_marker.error().code, transport::ErrorCode::ObjectNotFound);
}

// Passo 10: ControlReadBatch filters hidden marker from listings and presences
TEST(VaultTransportAdapterTest, ControlReadBatchFiltersHiddenMarker) {
    auto* raw_state = new NativeBatchState{};
    transport::Transport base_transport{
        .state = transport::TransportStateHandle{raw_state, [](void* p) noexcept {
            delete static_cast<NativeBatchState*>(p);
        }},
        .storage = transport::StorageOperations{
            .initialize = [](void*) -> transport::Result { return {}; },
            .put = [](void*, const std::filesystem::path&, std::string_view) -> transport::Result { return {}; },
            .get = [](void*, std::string_view, const std::filesystem::path&) -> transport::Result { return {}; },
            .presence = [](void*, std::string_view) -> transport::PresenceResult { return transport::Presence::Present; },
            .list = [](void*) -> transport::ListingResult { return std::vector<std::string>{}; },
            .control_read_batch = [](void* ctx, const transport::ControlReadBatchRequest&) -> transport::ControlReadBatchResponse {
                auto* s = static_cast<NativeBatchState*>(ctx);
                if (s->magic != NativeBatchState::kMagic) {
                    return std::unexpected(transport::Error{.code = transport::ErrorCode::InvalidContext, .message = "control_read ctx mismatch"});
                }
                s->context_matched = true;
                transport::ControlReadBatchResult r;
                r.listings.push_back({"file1.bin", "owner.marker", "file2.bin"});
                r.presences = {transport::Presence::Present, transport::Presence::Present};
                return r;
            },
            .remove = [](void*, std::string_view) -> transport::RemovalResult { return transport::Removal::Removed; },
        },
    };

    auto vault_transport = runner::make_vault_transport(base_transport, "owner.marker");
    EXPECT_NE(vault_transport.storage.control_read_batch, nullptr);

    transport::ControlReadBatchRequest req{
        .list_prefixes = {"prefix"},
        .presence_identifiers = {"file1.bin", "owner.marker"},
    };

    auto resp = transport::control_read_batch(vault_transport, req);
    ASSERT_TRUE(resp.has_value());
    EXPECT_TRUE(raw_state->context_matched);
    ASSERT_EQ(resp->listings.size(), 1U);
    EXPECT_EQ(resp->listings[0], (std::vector<std::string>{"file1.bin", "file2.bin"}));
    ASSERT_EQ(resp->presences.size(), 2U);
    EXPECT_EQ(resp->presences[0], transport::Presence::Present);
    EXPECT_EQ(resp->presences[1], transport::Presence::Absent);
}

// Passo 14: Regressão contra futuras capabilities copiadas cegamente
TEST(VaultTransportAdapterTest, NoCallbacksDirectlyCopiedFromBase) {
    auto dummy_init = [](void*) -> transport::Result { return {}; };
    auto dummy_put = [](void*, const std::filesystem::path&, std::string_view) -> transport::Result { return {}; };
    auto dummy_put_batch = [](void*, const transport::PutBatch&) -> transport::Result { return {}; };
    auto dummy_get = [](void*, std::string_view, const std::filesystem::path&) -> transport::Result { return {}; };
    auto dummy_get_batch = [](void*, const transport::GetBatch&) -> transport::Result { return {}; };
    auto dummy_copy = [](void*, std::string_view, std::string_view) -> transport::Result { return {}; };
    auto dummy_presence = [](void*, std::string_view) -> transport::PresenceResult { return transport::Presence::Present; };
    auto dummy_list = [](void*) -> transport::ListingResult { return std::vector<std::string>{}; };
    auto dummy_list_prefix = [](void*, std::string_view) -> transport::ListingResult { return std::vector<std::string>{}; };
    auto dummy_hash = [](void*, std::string_view, std::string_view) -> std::expected<std::string, transport::Error> { return ""; };
    auto dummy_hash_batch = [](void*, const transport::PhysicalHashBatchRequest&) -> transport::PhysicalHashBatchResult { return transport::PhysicalHashBatchReport{}; };
    auto dummy_control_read = [](void*, const transport::ControlReadBatchRequest&) -> transport::ControlReadBatchResponse { return transport::ControlReadBatchResult{}; };
    auto dummy_remove = [](void*, std::string_view) -> transport::RemovalResult { return transport::Removal::Removed; };

    transport::Transport base_transport{
        .state = transport::TransportStateHandle{nullptr, [](void*) noexcept {}},
        .storage = transport::StorageOperations{
            .initialize = dummy_init,
            .put = dummy_put,
            .put_batch = dummy_put_batch,
            .get = dummy_get,
            .get_batch = dummy_get_batch,
            .copy = dummy_copy,
            .presence = dummy_presence,
            .list = dummy_list,
            .list_prefix = dummy_list_prefix,
            .physical_hash = dummy_hash,
            .physical_hash_batch = dummy_hash_batch,
            .control_read_batch = dummy_control_read,
            .remove = dummy_remove,
            .physical_hash_batch_min_objects = 5,
        },
    };

    auto vault = runner::make_vault_transport(base_transport, "owner.marker");

    // Invariant: NO function pointer may be copied directly from base
    EXPECT_NE(vault.storage.initialize, base_transport.storage.initialize);
    EXPECT_NE(vault.storage.put, base_transport.storage.put);
    EXPECT_NE(vault.storage.put_batch, base_transport.storage.put_batch);
    EXPECT_NE(vault.storage.get, base_transport.storage.get);
    EXPECT_NE(vault.storage.get_batch, base_transport.storage.get_batch);
    EXPECT_NE(vault.storage.copy, base_transport.storage.copy);
    EXPECT_NE(vault.storage.presence, base_transport.storage.presence);
    EXPECT_NE(vault.storage.list, base_transport.storage.list);
    EXPECT_NE(vault.storage.list_prefix, base_transport.storage.list_prefix);
    EXPECT_NE(vault.storage.physical_hash, base_transport.storage.physical_hash);
    EXPECT_NE(vault.storage.physical_hash_batch, base_transport.storage.physical_hash_batch);
    EXPECT_NE(vault.storage.control_read_batch, base_transport.storage.control_read_batch);
    EXPECT_NE(vault.storage.remove, base_transport.storage.remove);
}

// Passo 16: Error code real do integrity::garbage_collect preservado
TEST(GcLiveRunnerDiagnosisTest, PreservesRealIntegrityErrorCode) {
    FakeHarness harness{"error-code-preservation"};
    auto options = harness.make_options();
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    const auto report = runner::run(
        options,
        &parent,
        &child,
        [](const auto&, auto&, auto) -> std::expected<integrity::GarbageCollectResult, integrity::Error> {
            return std::unexpected(integrity::Error{
                .code = integrity::ErrorCode::TransportFailure,
                .detail = "simulated remote connection reset",
            });
        });

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.gc.result, "FAILED");
    ASSERT_TRUE(report.gc.error_category.has_value());
    EXPECT_EQ(*report.gc.error_category, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(runner::integrity_error_code_name(*report.gc.error_category), "transport_failure");
    EXPECT_EQ(report.gc.error_detail_sanitized, "simulated remote connection reset");

    auto json = runner::to_json(report);
    EXPECT_EQ(json["gc"]["error_category"], "transport_failure");
    EXPECT_EQ(json["gc"]["error_detail_sanitized"], "simulated remote connection reset");
}

// Passo 18: Métricas capturadas mesmo em failure path
TEST(GcLiveRunnerDiagnosisTest, CapturesMetricsOnFailurePath) {
    FakeHarness harness{"metrics-failure"};
    auto options = harness.make_options();
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    const auto report = runner::run(
        options,
        &parent,
        &child,
        [](const auto&, auto&, auto) -> std::expected<integrity::GarbageCollectResult, integrity::Error> {
            kasumi::platform::perf_trace::count("verified copy native copy");
            kasumi::platform::perf_trace::count("verified copy native copy successes");
            return std::unexpected(integrity::Error{
                .code = integrity::ErrorCode::IntegrityFailure,
                .detail = "barrier check failed",
            });
        });

    EXPECT_EQ(report.status, "FAILED");
    EXPECT_EQ(report.gc.result, "FAILED");
    EXPECT_EQ(report.metrics.verified_copy_native_copy, 1U);
    EXPECT_EQ(report.metrics.verified_copy_native_copy_successes, 1U);
}

// Passo 20: Teste integrado offline com base native-capable
TEST(GcLiveRunnerIntegratedTest, FullExecutionWithNativeBatchStorage) {
    FakeHarness harness{"integrated-native-batch"};
    auto options = harness.make_options();
    auto parent = harness.make_parent_transport();
    auto child = harness.make_child_transport();

    std::size_t native_get_batch_count = 0;
    static std::size_t* s_batch_count = nullptr;
    s_batch_count = &native_get_batch_count;

    child.storage.get_batch = [](void* ctx, const transport::GetBatch& batch) -> transport::Result {
        auto* state = static_cast<FakeState*>(ctx);
        if (s_batch_count) {
            (*s_batch_count)++;
        }
        for (const auto& id : batch.identifiers) {
            const auto source = batch.source_prefix.empty() ? id : batch.source_prefix + "/" + id;
            auto it = state->objects.find(source);
            if (it == state->objects.end()) {
                return std::unexpected(transport::Error{
                    .code = transport::ErrorCode::ObjectNotFound,
                    .message = "object not found in native get_batch",
                });
            }
            auto dest = batch.destination_root / kasumi::platform::path::from_utf8(id);
            std::filesystem::create_directories(dest.parent_path());
            std::ofstream stream(dest, std::ios::binary);
            stream.write(reinterpret_cast<const char*>(it->second.data()), static_cast<std::streamsize>(it->second.size()));
        }
        return {};
    };

    const auto report = runner::run(options, &parent, &child);
    s_batch_count = nullptr;

    EXPECT_EQ(report.status, "PASS");
    EXPECT_EQ(report.stage_reached, runner::LiveGcStage::CleanupCompleted);
    EXPECT_EQ(report.gc.called, true);
    EXPECT_EQ(report.gc.call_count, 1U);
    EXPECT_EQ(report.gc.result, "SUCCESS");
    EXPECT_EQ(report.gc.candidate_objects, 1U);
    EXPECT_EQ(report.gc.quarantined_objects, 1U);
    EXPECT_EQ(report.cleanup.result, "removed");
    EXPECT_GT(native_get_batch_count, 0U);
}

} // namespace
