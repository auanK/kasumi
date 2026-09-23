#include "../../operational/remote_copy_smoke_support.hpp"

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
};

std::string full_identifier(const FakeState& state, std::string_view identifier) {
    return state.scope_root.empty()
               ? std::string{identifier}
               : state.scope_root + "/" + std::string{identifier};
}

void destroy_state(void* context) noexcept {
    delete static_cast<FakeState*>(context);
}

transport::Result initialize(void*) { return {}; }

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
    static_cast<FakeState*>(context)->objects[std::string{identifier}] =
        std::move(bytes);
    return {};
}

transport::Result get(void* context,
                      std::string_view identifier,
                      const std::filesystem::path& destination) {
    auto* state = static_cast<FakeState*>(context);
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
    std::vector<std::string> identifiers;
    for (const auto& [identifier, _] : state->objects) {
        identifiers.push_back(identifier);
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
