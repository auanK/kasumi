#include "../../operational/remote_copy_smoke_support.hpp"
#include "../../operational/gc_live_preflight_support.hpp"

#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <chrono>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

namespace smoke = kasumi::operational::remote_copy_smoke;
namespace transport = kasumi::transport;

smoke::CopySmokeOutcome verified_native_copy() {
    return smoke::CopySmokeOutcome{
        .native_copy_succeeded = true,
        .source_hash_valid = true,
        .destination_hash_valid = true,
        .hashes_match = true,
        .destination_bytes_match = true,
        .source_remains = true,
        .cleanup_succeeded = true,
    };
}

smoke::ReadinessAttempt readiness_attempt(
    std::size_t index,
    std::chrono::milliseconds elapsed,
    smoke::ReadinessPresence presence,
    smoke::ReadinessHash hash,
    std::string sha256 = {},
    std::optional<transport::ErrorCode> hash_error = std::nullopt,
    std::string hash_error_message = {}) {
    return smoke::ReadinessAttempt{
        .attempt_index = index,
        .elapsed_since_reference = elapsed,
        .presence = presence,
        .physical_hash = hash,
        .physical_hash_error = hash_error,
        .physical_hash_error_message = std::move(hash_error_message),
        .sha256 = std::move(sha256),
    };
}

struct FakeState {
    std::map<std::string, std::string> objects;
    std::set<std::string> existing_prefixes;
    std::set<std::string> empty_success_prefixes;
    std::vector<std::string> removed;
    std::string scope_root;
    bool storage_root_exists = true;
    std::size_t initialize_count = 0;
    std::size_t put_count = 0;
    std::size_t get_count = 0;
};

std::string full_identifier(const FakeState& state, std::string_view identifier) {
    return state.scope_root.empty()
               ? std::string{identifier}
               : state.scope_root + "/" + std::string{identifier};
}

void destroy_state(void* context) noexcept {
    delete static_cast<FakeState*>(context);
}

transport::Result initialize(void* context) {
    auto* state = static_cast<FakeState*>(context);
    ++state->initialize_count;
    state->storage_root_exists = true;
    return {};
}

transport::Result put(void* context,
                      const std::filesystem::path& source,
                      std::string_view identifier) {
    std::ifstream input(source, std::ios::binary);
    if (!input) {
        return std::unexpected(transport::Error{
            .code = transport::ErrorCode::ObjectNotFound,
            .message = "local test file missing"});
    }
    std::string bytes{std::istreambuf_iterator<char>{input}, {}};
    auto* state = static_cast<FakeState*>(context);
    ++state->put_count;
    state->objects[full_identifier(*state, identifier)] = std::move(bytes);
    return {};
}

transport::Result get(void* context,
                      std::string_view identifier,
                      const std::filesystem::path& destination) {
    auto* state = static_cast<FakeState*>(context);
    ++state->get_count;
    const auto found = state->objects.find(full_identifier(*state, identifier));
    if (found == state->objects.end()) {
        return std::unexpected(transport::Error{
            .code = transport::ErrorCode::ObjectNotFound,
            .message = "test object missing"});
    }
    std::ofstream output(destination, std::ios::binary | std::ios::trunc);
    output.write(found->second.data(),
                 static_cast<std::streamsize>(found->second.size()));
    return output ? transport::Result{} : transport::Result{std::unexpected(
                             transport::Error{.code = transport::ErrorCode::Io,
                                              .message = "write failed"})};
}

transport::PresenceResult presence(void* context, std::string_view identifier) {
    auto* state = static_cast<FakeState*>(context);
    return state->objects.contains(full_identifier(*state, identifier))
               ? transport::Presence::Present
               : transport::Presence::Absent;
}

transport::ListingResult list(void* context) {
    auto* state = static_cast<FakeState*>(context);
    if (!state->storage_root_exists) {
        return std::unexpected(transport::Error{
            .code = transport::ErrorCode::StorageNotFound,
            .message = "storage root missing"});
    }
    std::vector<std::string> identifiers;
    for (const auto& [identifier, _] : state->objects) {
        if (state->scope_root.empty()) {
            identifiers.push_back(identifier);
        } else {
            const auto marker = state->scope_root + "/";
            if (identifier.starts_with(marker)) {
                identifiers.push_back(identifier.substr(marker.size()));
            }
        }
    }
    return identifiers;
}

transport::ListingResult list_prefix(void* context, std::string_view prefix) {
    auto* state = static_cast<FakeState*>(context);
    std::vector<std::string> identifiers;
    const auto marker = std::string{prefix} + "/";
    for (const auto& [identifier, _] : state->objects) {
        if (identifier.starts_with(marker)) {
            identifiers.push_back(identifier.substr(marker.size()));
        }
    }
    if (identifiers.empty() &&
        !state->existing_prefixes.contains(std::string{prefix}) &&
        !state->empty_success_prefixes.contains(std::string{prefix})) {
        return std::unexpected(transport::Error{
            .code = transport::ErrorCode::StorageNotFound,
            .message = "prefix missing"});
    }
    return identifiers;
}

transport::RemovalResult remove(void* context, std::string_view identifier) {
    auto* state = static_cast<FakeState*>(context);
    const auto full = full_identifier(*state, identifier);
    state->removed.push_back(full);
    return state->objects.erase(full) != 0
               ? transport::Removal::Removed
               : transport::Removal::AlreadyAbsent;
}

transport::Transport make_transport(FakeState*& state) {
    state = new FakeState;
    return transport::Transport{
        .state = transport::TransportStateHandle{state, destroy_state},
        .storage = transport::StorageOperations{
            .initialize = initialize,
            .put = put,
            .get = get,
            .presence = presence,
            .list = list,
            .list_prefix = list_prefix,
            .remove = remove,
        }};
}

TEST(RemoteCopySmokeSafetyTest, RejectsRemoteRootAndUnsafeParentPaths) {
    for (const auto value : {"remote:", "remote:.", "remote:a/../b",
                             "remote:a//b", "remote:a\\b", "remote:a/ b",
                             "C:/local/path", "/tmp/remote"}) {
        EXPECT_FALSE(smoke::parse_remote_parent(value)) << value;
    }
    EXPECT_TRUE(smoke::parse_remote_parent("archive:test-parent"));
}

TEST(RemoteCopySmokeSafetyTest, ChildNamespaceDiffersForEachRunNonce) {
    const auto first = smoke::child_namespace("0123456789abcdef0123456789abcdef");
    const auto second = smoke::child_namespace("fedcba9876543210fedcba9876543210");
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    EXPECT_NE(*first, *second);
    EXPECT_TRUE(first->starts_with("kasumi-copy-smoke-"));
}

TEST(RemoteCopySmokeSafetyTest, RefusesAnExistingEmptyChildNamespace) {
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    state->existing_prefixes.insert(
        "kasumi-copy-smoke-0123456789abcdef0123456789abcdef");

    const auto result =
        smoke::require_unused_child(
            storage,
            "kasumi-copy-smoke-0123456789abcdef0123456789abcdef");

    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, transport::ErrorCode::InvalidIdentifier);
    EXPECT_NE(result.error().message.find("ambiguous"), std::string::npos);
}

TEST(RemoteCopySmokeSafetyTest,
     RefusesToAssumeAnEmptySuccessfulListingIsUnused) {
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    constexpr std::string_view child =
        "kasumi-copy-smoke-0123456789abcdef0123456789abcdef";
    state->empty_success_prefixes.insert(std::string{child});

    const auto result = smoke::require_unused_child(storage, child);

    ASSERT_FALSE(result);
    EXPECT_NE(result.error().message.find("ambiguous"), std::string::npos);
}

TEST(RemoteCopySmokeSafetyTest, CleanupNeverRemovesOutsideTheChild) {
    auto workspace = kasumi::test::make_temp_workspace("remote-copy-scope");
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    constexpr std::string_view child =
        "kasumi-copy-smoke-0123456789abcdef0123456789abcdef";
    state->scope_root = std::string{child};
    state->objects[std::string{child} + "/owner.marker"] = "owned";
    state->objects["outside/object"] = "preserve";

    const auto result = smoke::cleanup_owned_child(
        storage,
        child,
        "owned",
        {std::string{child} + "/source", "outside/object"},
        kasumi::test::workspace_root(workspace));

    EXPECT_EQ(result.result, "refused");
    EXPECT_TRUE(state->removed.empty());
    EXPECT_TRUE(state->objects.contains("outside/object"));
}

TEST(RemoteCopySmokeSafetyTest, RefusesCleanupWithAmbiguousOwnershipMarker) {
    auto workspace = kasumi::test::make_temp_workspace("remote-copy-owner");
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    constexpr std::string_view child =
        "kasumi-copy-smoke-0123456789abcdef0123456789abcdef";
    state->scope_root = std::string{child};
    state->objects[std::string{child} + "/owner.marker"] = "someone-else";
    state->objects[std::string{child} + "/source"] = "payload";

    const auto result = smoke::cleanup_owned_child(
        storage,
        child,
        "this-run",
        {std::string{child} + "/source"},
        kasumi::test::workspace_root(workspace));

    EXPECT_EQ(result.result, "refused");
    EXPECT_TRUE(state->removed.empty());
    EXPECT_TRUE(state->objects.contains(std::string{child} + "/source"));
}

TEST(RemoteCopySmokeSafetyTest, RemovesOnlyOwnedObjectsInsideTheChild) {
    auto workspace = kasumi::test::make_temp_workspace("remote-copy-cleanup");
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    constexpr std::string_view child =
        "kasumi-copy-smoke-0123456789abcdef0123456789abcdef";
    state->scope_root = std::string{child};
    state->objects[std::string{child} + "/owner.marker"] = "this-run";
    state->objects[std::string{child} + "/source"] = "payload";
    state->objects["outside/object"] = "preserve";

    const auto result = smoke::cleanup_owned_child(
        storage,
        child,
        "this-run",
        {std::string{child} + "/source"},
        kasumi::test::workspace_root(workspace));

    EXPECT_EQ(result.result, "removed");
    EXPECT_EQ(result.removed_objects, 2U);
    const std::vector<std::string> expected_removed{
        std::string{child} + "/source",
        std::string{child} + "/owner.marker"};
    EXPECT_EQ(state->removed, expected_removed);
    EXPECT_TRUE(state->objects.contains("outside/object"));
}

namespace gc_live = kasumi::operational::gc_live_preflight;

gc_live::PreInitializeObservation proven_absent_observation(
    const smoke::RemoteParent& parent,
    std::string_view child) {
    return gc_live::PreInitializeObservation{
        .transport = {.result = "FAILED",
                      .error_category = transport::ErrorCode::StorageNotFound,
                      .error_message = "remote objects directory does not exist"},
        .raw_rc = {.endpoint = "operations/list",
                   .request_fs = parent.remote_name + ":",
                   .request_remote = parent.directory + "/" +
                                     std::string{child},
                   .result = "FAILED",
                   .native_status = 404,
                   .error_category = transport::ErrorCode::ProtocolFailure,
                   .error_message = "endpoint=operations/list: error in ListJSON: directory not found"},
    };
}

TEST(GcLivePreflightTest, ChildNamespaceUsesOnlyItsDedicatedPrefix) {
    const auto first = gc_live::child_namespace(
        "0123456789abcdef0123456789abcdef");
    const auto second = gc_live::child_namespace(
        "fedcba9876543210fedcba9876543210");
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    ASSERT_TRUE(parent);
    EXPECT_NE(*first, *second);
    EXPECT_EQ(*first,
              "kasumi-gc-live-0123456789abcdef0123456789abcdef");
    EXPECT_TRUE(gc_live::valid_child(*first));
    EXPECT_FALSE(gc_live::valid_child(
        "kasumi-copy-smoke-0123456789abcdef0123456789abcdef"));
    EXPECT_FALSE(gc_live::child_location(
        *parent, "kasumi-copy-smoke-0123456789abcdef0123456789abcdef"));

    auto mismatched_parent = *parent;
    mismatched_parent.location = "archive:other-test-parent";
    EXPECT_FALSE(gc_live::child_location(mismatched_parent, *first));
    EXPECT_FALSE(gc_live::child_location(
        smoke::RemoteParent{.location = "archive:",
                            .remote_name = "archive",
                            .directory = ""},
        *first));
}

TEST(GcLivePreflightTest, StrictMissingDirectoryEvidenceAllowsInitialize) {
    constexpr std::string_view child =
        "kasumi-gc-live-0123456789abcdef0123456789abcdef";
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(parent);
    const auto observation = proven_absent_observation(*parent, child);

    const auto classification =
        gc_live::classify_pre_initialize(observation, *parent, child);

    EXPECT_EQ(classification.disposition, gc_live::ChildDisposition::Unused);
}

TEST(GcLivePreflightTest, ExistingObjectsAndExistingEmptyChildAreRefused) {
    constexpr std::string_view child =
        "kasumi-gc-live-0123456789abcdef0123456789abcdef";
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(parent);

    auto existing = proven_absent_observation(*parent, child);
    existing.transport = {.result = "SUCCESS", .entry_count = 1};
    EXPECT_EQ(gc_live::classify_pre_initialize(existing, *parent, child)
                  .disposition,
              gc_live::ChildDisposition::Existing);

    auto empty = proven_absent_observation(*parent, child);
    empty.transport = {.result = "SUCCESS", .entry_count = 0};
    empty.raw_rc = {.endpoint = "operations/list",
                    .request_fs = parent->remote_name + ":",
                    .request_remote = parent->directory + "/" +
                                      std::string{child},
                    .result = "SUCCESS",
                    .entry_count = 0};
    const auto empty_classification =
        gc_live::classify_pre_initialize(empty, *parent, child);
    EXPECT_EQ(empty_classification.disposition,
              gc_live::ChildDisposition::Refused);
    EXPECT_NE(empty_classification.reason.find("empty"), std::string::npos);
}

TEST(GcLivePreflightTest,
     NormalizedStorageNotFoundWithoutStrictRcEvidenceIsRefused) {
    constexpr std::string_view child =
        "kasumi-gc-live-0123456789abcdef0123456789abcdef";
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(parent);

    auto observation = proven_absent_observation(*parent, child);
    observation.raw_rc = {};
    EXPECT_EQ(gc_live::classify_pre_initialize(observation, *parent, child)
                  .disposition,
              gc_live::ChildDisposition::Refused);
    const auto report = gc_live::to_json(
        observation,
        gc_live::classify_pre_initialize(observation, *parent, child));
    EXPECT_EQ(report["raw_rc_native_status"], nullptr);
    EXPECT_EQ(report["raw_rc_error_category"], nullptr);
    EXPECT_EQ(report["raw_rc_error_message_sanitized"], nullptr);

    for (const auto* message : {"generic HTTP 404",
                                "couldn't find method \"operations/list\"",
                                "object not found",
                                "permission denied"}) {
        auto ambiguous = proven_absent_observation(*parent, child);
        ambiguous.raw_rc.error_message = message;
        EXPECT_EQ(gc_live::classify_pre_initialize(ambiguous, *parent, child)
                      .disposition,
                  gc_live::ChildDisposition::Refused)
            << message;
    }
}

TEST(GcLivePreflightTest, NonAbsenceTransportErrorsAreRefused) {
    constexpr std::string_view child =
        "kasumi-gc-live-0123456789abcdef0123456789abcdef";
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(parent);
    for (const auto code : {transport::ErrorCode::PermissionDenied,
                            transport::ErrorCode::Io,
                            transport::ErrorCode::Timeout,
                            transport::ErrorCode::ProtocolFailure}) {
        auto observation = proven_absent_observation(*parent, child);
        observation.transport.error_category = code;
        EXPECT_EQ(gc_live::classify_pre_initialize(observation, *parent, child)
                      .disposition,
                  gc_live::ChildDisposition::Refused)
            << transport::error_code_name(code);
    }
}

TEST(GcLivePreflightTest,
     InitializeThenEmptyPostListingAllowsVerifiedOwnershipMarker) {
    constexpr std::string_view child_name =
        "kasumi-gc-live-0123456789abcdef0123456789abcdef";
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(parent);
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    state->scope_root = std::string{child_name};
    state->storage_root_exists = false;
    gc_live::ChildStorage child{.parent = *parent,
                                .child = std::string{child_name},
                                .storage = std::move(storage)};
    const auto pre = proven_absent_observation(*parent, child_name);

    ASSERT_TRUE(gc_live::initialize_child(child, pre));
    const auto post = gc_live::observe_post_initialize(child);
    EXPECT_EQ(gc_live::classify_post_initialize(post),
              gc_live::PostInitializeDisposition::Empty);
    EXPECT_EQ(post.transport.entry_count, 0U);

    auto workspace = kasumi::test::make_temp_workspace("gc-live-owner");
    const auto marker_source =
        kasumi::test::workspace_path(workspace, "owner-source");
    const auto marker_readback =
        kasumi::test::workspace_path(workspace, "owner-readback");
    kasumi::test::write_text(marker_source, "run-token");
    ASSERT_TRUE(gc_live::establish_ownership_marker(
        child, post, "run-token", marker_source, marker_readback));
    EXPECT_EQ(state->put_count, 1U);
    EXPECT_TRUE(state->objects.contains(std::string{child_name} +
                                        "/owner.marker"));
}

TEST(GcLivePreflightTest, RefusedGatesNeverInitializeOrWriteOwnerMarker) {
    constexpr std::string_view child_name =
        "kasumi-gc-live-0123456789abcdef0123456789abcdef";
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(parent);
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    gc_live::ChildStorage child{.parent = *parent,
                                .child = std::string{child_name},
                                .storage = std::move(storage)};
    auto unproven = proven_absent_observation(*parent, child_name);
    unproven.raw_rc = {};

    const auto initialized = gc_live::initialize_child(child, unproven);
    EXPECT_FALSE(initialized);
    EXPECT_EQ(state->initialize_count, 0U);

    auto existing = proven_absent_observation(*parent, child_name);
    existing.transport = {.result = "SUCCESS", .entry_count = 1};
    EXPECT_FALSE(gc_live::initialize_child(child, existing));
    EXPECT_EQ(state->initialize_count, 0U);

    auto empty_existing = proven_absent_observation(*parent, child_name);
    empty_existing.transport = {.result = "SUCCESS", .entry_count = 0};
    empty_existing.raw_rc.result = "SUCCESS";
    empty_existing.raw_rc.entry_count = 0;
    EXPECT_FALSE(gc_live::initialize_child(child, empty_existing));
    EXPECT_EQ(state->initialize_count, 0U);

    const auto post = gc_live::PostInitializeObservation{
        .transport = {.result = "FAILED",
                      .error_category = transport::ErrorCode::StorageNotFound}};
    auto workspace = kasumi::test::make_temp_workspace("gc-live-no-owner");
    const auto marker_source =
        kasumi::test::workspace_path(workspace, "owner-source");
    const auto marker_readback =
        kasumi::test::workspace_path(workspace, "owner-readback");
    kasumi::test::write_text(marker_source, "run-token");
    EXPECT_FALSE(gc_live::establish_ownership_marker(
        child, post, "run-token", marker_source, marker_readback));
    EXPECT_EQ(state->put_count, 0U);

    const auto non_empty = gc_live::PostInitializeObservation{
        .transport = {.result = "SUCCESS", .entry_count = 1}};
    EXPECT_FALSE(gc_live::establish_ownership_marker(
        child, non_empty, "run-token", marker_source, marker_readback));
    EXPECT_EQ(state->put_count, 0U);
}

TEST(GcLivePreflightTest, PostInitializeRequiresSuccessfulEmptyListing) {
    for (const auto& observation : {
             gc_live::PostInitializeObservation{
                 .transport = {.result = "FAILED",
                               .error_category = transport::ErrorCode::StorageNotFound}},
             gc_live::PostInitializeObservation{
                 .transport = {.result = "SUCCESS", .entry_count = 1}},
             gc_live::PostInitializeObservation{
                 .transport = {.result = "FAILED",
                               .error_category = transport::ErrorCode::PermissionDenied}},
             gc_live::PostInitializeObservation{
                 .transport = {.result = "FAILED",
                               .error_category = transport::ErrorCode::Timeout}},
             gc_live::PostInitializeObservation{
                 .transport = {.result = "FAILED",
                               .error_category = transport::ErrorCode::Io}},
             gc_live::PostInitializeObservation{
                 .transport = {.result = "FAILED",
                               .error_category = transport::ErrorCode::ProtocolFailure}}}) {
        EXPECT_EQ(gc_live::classify_post_initialize(observation),
                  gc_live::PostInitializeDisposition::Refused);
    }
}

TEST(GcLivePreflightTest, CleanupRefusesMissingOrMismatchedOwnership) {
    constexpr std::string_view child_name =
        "kasumi-gc-live-0123456789abcdef0123456789abcdef";
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(parent);
    auto workspace = kasumi::test::make_temp_workspace("gc-live-cleanup-refused");
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    state->scope_root = std::string{child_name};
    gc_live::ChildStorage child{.parent = *parent,
                                .child = std::string{child_name},
                                .storage = std::move(storage)};

    const auto missing = gc_live::cleanup_owned_child(
        child, "run-token", {"payload.bin"},
        kasumi::test::workspace_root(workspace));
    EXPECT_EQ(missing.result, "refused");
    EXPECT_TRUE(state->removed.empty());

    state->objects[std::string{child_name} + "/owner.marker"] = "other-run";
    state->objects[std::string{child_name} + "/payload.bin"] = "payload";
    const auto mismatched = gc_live::cleanup_owned_child(
        child, "run-token", {"payload.bin"},
        kasumi::test::workspace_root(workspace));
    EXPECT_EQ(mismatched.result, "refused");
    EXPECT_TRUE(state->removed.empty());
    EXPECT_TRUE(state->objects.contains(std::string{child_name} +
                                        "/payload.bin"));
}

TEST(GcLivePreflightTest, CleanupRejectsUnsafeIdentifiersBeforeRemoteRead) {
    constexpr std::string_view child_name =
        "kasumi-gc-live-0123456789abcdef0123456789abcdef";
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(parent);
    auto workspace = kasumi::test::make_temp_workspace("gc-live-cleanup-path");
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    state->scope_root = std::string{child_name};
    state->objects[std::string{child_name} + "/owner.marker"] = "run-token";
    gc_live::ChildStorage child{.parent = *parent,
                                .child = std::string{child_name},
                                .storage = std::move(storage)};

    const auto result = gc_live::cleanup_owned_child(
        child, "run-token", {"../outside.bin"},
        kasumi::test::workspace_root(workspace));

    EXPECT_EQ(result.result, "refused");
    EXPECT_EQ(state->get_count, 0U);
    EXPECT_TRUE(state->removed.empty());
}

TEST(GcLivePreflightTest, CleanupRefusesExistingLocalOwnershipCheckPath) {
    constexpr std::string_view child_name =
        "kasumi-gc-live-0123456789abcdef0123456789abcdef";
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(parent);
    auto workspace = kasumi::test::make_temp_workspace("gc-live-cleanup-local-path");
    const auto check_path = kasumi::test::workspace_path(
        workspace, "gc-live-owner-check.tmp");
    kasumi::test::write_text(check_path, "do-not-overwrite");
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    state->scope_root = std::string{child_name};
    state->objects[std::string{child_name} + "/owner.marker"] = "run-token";
    gc_live::ChildStorage child{.parent = *parent,
                                .child = std::string{child_name},
                                .storage = std::move(storage)};

    const auto result = gc_live::cleanup_owned_child(
        child, "run-token", {"payload.bin"},
        kasumi::test::workspace_root(workspace));

    EXPECT_EQ(result.result, "refused");
    EXPECT_EQ(state->get_count, 0U);
    EXPECT_TRUE(state->removed.empty());
    std::ifstream input(check_path, std::ios::binary);
    const std::string contents{std::istreambuf_iterator<char>{input}, {}};
    EXPECT_EQ(contents, "do-not-overwrite");
}

TEST(GcLivePreflightTest, CleanupRemovesOnlyExplicitObjectsAfterOwnerReadback) {
    constexpr std::string_view child_name =
        "kasumi-gc-live-0123456789abcdef0123456789abcdef";
    const auto parent = smoke::parse_remote_parent("archive:dedicated-test-parent");
    ASSERT_TRUE(parent);
    auto workspace = kasumi::test::make_temp_workspace("gc-live-cleanup-owned");
    FakeState* state = nullptr;
    auto storage = make_transport(state);
    state->scope_root = std::string{child_name};
    state->objects[std::string{child_name} + "/owner.marker"] = "run-token";
    state->objects[std::string{child_name} + "/payload.bin"] = "payload";
    state->objects["outside/payload.bin"] = "preserve";
    gc_live::ChildStorage child{.parent = *parent,
                                .child = std::string{child_name},
                                .storage = std::move(storage)};

    const auto result = gc_live::cleanup_owned_child(
        child, "run-token", {"payload.bin"},
        kasumi::test::workspace_root(workspace));

    EXPECT_EQ(result.result, "removed");
    EXPECT_EQ(state->removed,
              (std::vector<std::string>{std::string{child_name} +
                                            "/payload.bin",
                                        std::string{child_name} +
                                            "/owner.marker"}));
    EXPECT_TRUE(state->objects.contains("outside/payload.bin"));
}

TEST(RemoteCopySmokeSafetyTest, ReportsUnsupportedHashAndCopyErrorsInJson) {
    const auto hash = smoke::to_json(smoke::OperationRecord{
        .name = "source_physical_hash",
        .result = "UNSUPPORTED",
        .elapsed_ms = 1.25,
        .error_category = transport::ErrorCode::Unsupported,
    });
    EXPECT_EQ(hash.at("result"), "UNSUPPORTED");
    EXPECT_EQ(hash.at("error_category"), "unsupported");
    EXPECT_DOUBLE_EQ(hash.at("elapsed_ms"), 1.25);

    const auto copy = smoke::to_json(smoke::OperationRecord{
        .name = "copy",
        .result = "FAILED",
        .elapsed_ms = 3.5,
        .error_category = transport::ErrorCode::Io,
    });
    EXPECT_EQ(copy.at("result"), "FAILED");
    EXPECT_EQ(copy.at("error_category"), "io");
}

TEST(RemoteCopySmokeJsonTest, OmitsErrorCategoryAsJsonNullForOperations) {
    const auto operation = smoke::to_json(smoke::OperationRecord{
        .name = "successful_operation",
        .result = "SUCCESS",
    });

    EXPECT_TRUE(operation.at("error_category").is_null())
        << operation.dump();
}

TEST(RemoteCopySmokeJsonTest, OmitsErrorCategoryAsJsonNullForCleanup) {
    const auto cleanup = smoke::to_json(smoke::CleanupResult{
        .result = "removed",
    });

    EXPECT_TRUE(cleanup.at("error_category").is_null()) << cleanup.dump();
}

TEST(RemoteCopySmokeReadinessTest, ImmediateHashIsReady) {
    const auto attempts = std::array{
        readiness_attempt(1,
                          std::chrono::milliseconds{0},
                          smoke::ReadinessPresence::Present,
                          smoke::ReadinessHash::Valid,
                          std::string(64, 'a'))};

    EXPECT_EQ(smoke::classify_readiness(attempts, std::chrono::seconds{8}),
              smoke::ReadinessClassification::Ready);
}

TEST(RemoteCopySmokeReadinessTest, LaterHashIsReadyAfterDelay) {
    const auto attempts = std::array{
        readiness_attempt(1,
                          std::chrono::milliseconds{0},
                          smoke::ReadinessPresence::Present,
                          smoke::ReadinessHash::ObjectNotFound,
                          {},
                          transport::ErrorCode::ObjectNotFound,
                          "not visible yet"),
        readiness_attempt(2,
                          std::chrono::milliseconds{250},
                          smoke::ReadinessPresence::Present,
                          smoke::ReadinessHash::Valid,
                          std::string(64, 'b'))};

    EXPECT_EQ(smoke::classify_readiness(attempts, std::chrono::seconds{8}),
              smoke::ReadinessClassification::ReadyAfterDelay);
}

TEST(RemoteCopySmokeReadinessTest,
     PresentWithObjectNotFoundThroughDeadlineIsContradictory) {
    const auto schedule = smoke::readiness_schedule();
    std::array<smoke::ReadinessAttempt, 6> attempts;
    for (std::size_t index = 0; index < schedule.size(); ++index) {
        attempts[index] = readiness_attempt(
            index + 1,
            schedule[index],
            index == 0 ? smoke::ReadinessPresence::Absent
                       : smoke::ReadinessPresence::Present,
            smoke::ReadinessHash::ObjectNotFound,
            {},
            transport::ErrorCode::ObjectNotFound,
            "not found");
    }

    EXPECT_EQ(smoke::classify_readiness(attempts, std::chrono::seconds{8}),
              smoke::ReadinessClassification::FailedContradictoryVisibility);
}

TEST(RemoteCopySmokeReadinessTest, UnsupportedHashStopsAsUnsupported) {
    const auto attempts = std::array{
        readiness_attempt(1,
                          std::chrono::milliseconds{0},
                          smoke::ReadinessPresence::Present,
                          smoke::ReadinessHash::Unsupported,
                          {},
                          transport::ErrorCode::Unsupported,
                          "sha256 unsupported")};

    EXPECT_EQ(smoke::classify_readiness(attempts, std::chrono::seconds{8}),
              smoke::ReadinessClassification::Unsupported);
}

TEST(RemoteCopySmokeReadinessTest, GenuineHashFailureIsFailed) {
    const auto attempts = std::array{
        readiness_attempt(1,
                          std::chrono::milliseconds{0},
                          smoke::ReadinessPresence::Present,
                          smoke::ReadinessHash::Failed,
                          {},
                          transport::ErrorCode::Io,
                          "connection failed")};

    EXPECT_EQ(smoke::classify_readiness(attempts, std::chrono::seconds{8}),
              smoke::ReadinessClassification::Failed);
}

TEST(RemoteCopySmokeReadinessTest,
     DestinationDelayRemainsVisibleInDiagnosticAttempts) {
    const std::vector attempts{
        readiness_attempt(1,
                          std::chrono::milliseconds{0},
                          smoke::ReadinessPresence::Present,
                          smoke::ReadinessHash::ObjectNotFound,
                          {},
                          transport::ErrorCode::ObjectNotFound,
                          "not visible yet"),
        readiness_attempt(2,
                          std::chrono::milliseconds{750},
                          smoke::ReadinessPresence::Present,
                          smoke::ReadinessHash::Valid,
                          std::string(64, 'c'))};

    EXPECT_EQ(smoke::classify_readiness(attempts, std::chrono::seconds{8}),
              smoke::ReadinessClassification::ReadyAfterDelay);
    const auto first_attempt = smoke::to_json(attempts.front());
    EXPECT_EQ(first_attempt.at("physical_hash").at("result"),
              "OBJECT_NOT_FOUND");
    EXPECT_EQ(first_attempt.at("physical_hash").at("error_category"),
              "object_not_found");
}

TEST(RemoteCopySmokeReadinessTest, RetryScheduleIsBoundedByEightSeconds) {
    const auto schedule = smoke::readiness_schedule();

    EXPECT_EQ(schedule.front(), std::chrono::milliseconds{0});
    EXPECT_EQ(schedule.back(), std::chrono::milliseconds{7750});
    EXPECT_LE(schedule.back(), std::chrono::seconds{8});
    const auto late_attempt = std::array{
        readiness_attempt(1,
                          std::chrono::milliseconds{8001},
                          smoke::ReadinessPresence::Present,
                          smoke::ReadinessHash::ObjectNotFound,
                          {},
                          transport::ErrorCode::ObjectNotFound,
                          "not found")};
    EXPECT_EQ(smoke::classify_readiness(late_attempt,
                                        std::chrono::seconds{8}),
              smoke::ReadinessClassification::Failed);
}

TEST(RemoteCopySmokeClassificationTest, NativeVerifiedCopyIsPass) {
    EXPECT_EQ(smoke::classify(verified_native_copy()), smoke::SmokeStatus::Pass);
}

TEST(RemoteCopySmokeClassificationTest,
     UnsupportedNativeCopyWithSuccessfulFallbackIsNotPass) {
    auto result = verified_native_copy();
    result.native_copy_succeeded = false;
    result.copy_unsupported = true;
    result.fallback_succeeded = true;

    EXPECT_EQ(smoke::classify(result), smoke::SmokeStatus::Unsupported);
}

TEST(RemoteCopySmokeClassificationTest, UnsupportedSourceHashIsUnsupported) {
    auto result = verified_native_copy();
    result.source_hash_valid = false;
    result.source_hash_unsupported = true;

    EXPECT_EQ(smoke::classify(result), smoke::SmokeStatus::Unsupported);
}

TEST(RemoteCopySmokeClassificationTest,
     UnsupportedDestinationHashIsUnsupported) {
    auto result = verified_native_copy();
    result.destination_hash_valid = false;
    result.destination_hash_unsupported = true;

    EXPECT_EQ(smoke::classify(result), smoke::SmokeStatus::Unsupported);
}

TEST(RemoteCopySmokeClassificationTest,
     IntegrityFailureOverridesUnsupportedCapability) {
    auto result = verified_native_copy();
    result.copy_unsupported = true;
    result.native_copy_succeeded = false;
    result.fallback_succeeded = true;
    result.destination_bytes_match = false;
    result.required_operation_failed = true;

    EXPECT_EQ(smoke::classify(result), smoke::SmokeStatus::Failed);
}

TEST(RemoteCopySmokeClassificationTest, CleanupFailureIsFailed) {
    auto result = verified_native_copy();
    result.cleanup_succeeded = false;
    result.required_operation_failed = true;

    EXPECT_EQ(smoke::classify(result), smoke::SmokeStatus::Failed);
}

} // namespace
