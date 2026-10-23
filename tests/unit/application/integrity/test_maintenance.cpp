#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "application/integrity/maintenance_test.hpp"
#include "core/maintenance.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

namespace {

using kasumi::application::history_storage::PublishedCommit;
namespace protocol = kasumi::application::history_storage::maintenance_protocol;
using IntegrityErrorCode = kasumi::application::integrity::ErrorCode;
using kasumi::runtime::RuntimeData;

using FsckNormalApi = std::expected<kasumi::application::integrity::FsckResult,
                                    kasumi::application::integrity::Error> (*)(
    const kasumi::runtime::RuntimeData&,
    kasumi::transport::Transport&,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE>,
    std::size_t,
    kasumi::application::integrity::FsckProgressCallback);
static_assert(std::is_same_v<decltype(&kasumi::application::integrity::fsck),
                             FsckNormalApi>);

[[maybe_unused]] auto fsck_without_worker_test_hooks(
    const kasumi::runtime::RuntimeData& runtime,
    kasumi::transport::Transport& storage,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key) {
    return kasumi::application::integrity::fsck(
        runtime,
        storage,
        key,
        4,
        kasumi::application::integrity::FsckProgressCallback{});
}

inline const auto& test_layout() {
    static const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    return layout;
}

RuntimeData runtime_data(TempWorkspace& workspace) {
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    EXPECT_TRUE(std::filesystem::create_directories(local));
    EXPECT_TRUE(std::filesystem::create_directories(profile));
    return RuntimeData{
        .local_dir = local,
        .database_path = profile / "db.sqlite",
        .key_path = profile / "key.bin",
        .storage_location = "unused",
    };
}

std::string put_content(kasumi::transport::Transport& transport,
                        TempWorkspace& workspace,
                        std::string_view content,
                        std::string_view suffix) {
    const auto identifier = kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string(content));
    const auto plain =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".plain");
    const auto encrypted =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".enc");
    kasumi::test::write_text(plain, content);
    EXPECT_TRUE(kasumi::crypto::encrypt_file(plain, encrypted, test_key()));
    EXPECT_TRUE(kasumi::transport::put(transport, encrypted, identifier));
    return identifier;
}

PublishedCommit publish_remote(kasumi::transport::Transport& transport,
                               TempWorkspace& workspace,
                               const Commit& commit) {
    auto published = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    EXPECT_TRUE(published.has_value()) << published.error().detail;
    return published ? *published : PublishedCommit{};
}

class BarrierOwnershipTest : public ::testing::Test {
protected:
    TempWorkspace workspace =
        kasumi::test::make_temp_workspace("barrier-ownership");
    FakeState* state = nullptr;
    kasumi::transport::Transport storage = make_fake_transport(state);
    protocol::RegistrationState barrier;

    void SetUp() override {
        ASSERT_TRUE(kasumi::transport::initialize(storage));
        state->physical_hash_supported = true;
        auto established = protocol::establish_barrier(
            storage, test_layout(), kasumi::test::workspace_root(workspace));
        ASSERT_TRUE(established.has_value()) << established.error().detail;
        barrier = std::move(*established);
        state->physical_hash_count = 0;
        state->get_count = 0;
        state->remove_count = 0;
    }

    void replace_barrier_bytes() {
        state->objects[test_layout().barrier_identifier] = {
            'f', 'o', 'r', 'e', 'i', 'g', 'n'};
    }
};

TEST_F(BarrierOwnershipTest, PhysicalHashMatchAndMismatchAvoidGet) {
    EXPECT_TRUE(protocol::verify_registration(barrier));
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);

    state->physical_hash_mismatch_identifier = test_layout().barrier_identifier;
    const auto mismatch = protocol::verify_registration(barrier);
    ASSERT_FALSE(mismatch.has_value());
    EXPECT_EQ(mismatch.error().code, protocol::ErrorCode::Blocked);
    EXPECT_EQ(state->physical_hash_count, 2U);
    EXPECT_EQ(state->get_count, 0U);
}

TEST_F(BarrierOwnershipTest, MissingBarrierFailsClosedWithoutGet) {
    state->objects.erase(test_layout().barrier_identifier);
    state->physical_hashes.erase(test_layout().barrier_identifier);

    const auto result = protocol::verify_registration(barrier);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, protocol::ErrorCode::Blocked);
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
}

TEST_F(BarrierOwnershipTest,
       UnsupportedHashUsesReadbackForMatchMismatchAndMissing) {
    state->physical_hash_unsupported_identifier =
        test_layout().barrier_identifier;
    EXPECT_TRUE(protocol::verify_registration(barrier));

    replace_barrier_bytes();
    const auto mismatch = protocol::verify_registration(barrier);
    ASSERT_FALSE(mismatch.has_value());
    EXPECT_EQ(mismatch.error().code, protocol::ErrorCode::Blocked);

    state->objects.erase(test_layout().barrier_identifier);
    const auto missing = protocol::verify_registration(barrier);
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, protocol::ErrorCode::Blocked);
    EXPECT_EQ(state->physical_hash_count, 3U);
    EXPECT_EQ(state->get_count, 3U);
}

TEST_F(BarrierOwnershipTest, TransportErrorsFailClosedWithoutGet) {
    using kasumi::transport::ErrorCode;
    for (const auto code : {ErrorCode::Timeout,
                            ErrorCode::BackendUnavailable,
                            ErrorCode::PermissionDenied,
                            ErrorCode::ProtocolFailure}) {
        state->physical_hash_failure = code;
        const auto result = protocol::verify_registration(barrier);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, protocol::ErrorCode::TransportFailure);
        EXPECT_EQ(state->get_count, 0U);
        state->physical_hash_failure.reset();
    }
    EXPECT_EQ(state->physical_hash_count, 4U);
}

TEST_F(BarrierOwnershipTest, MalformedHashFailsClosedWithoutGet) {
    for (const auto& value : {std::string{},
                              std::string(64, 'A'),
                              std::string(64, 'g'),
                              std::string{"abc"}}) {
        state->physical_hash_override = value;
        const auto result = protocol::verify_registration(barrier);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code,
                  protocol::ErrorCode::VerificationFailure);
        EXPECT_EQ(state->get_count, 0U);
        state->physical_hash_override.reset();
    }
    EXPECT_EQ(state->physical_hash_count, 4U);
}

TEST_F(BarrierOwnershipTest, ReleaseVerifiesHashBeforeRemovingOwnedBarrier) {
    ASSERT_TRUE(protocol::release_registration(barrier));
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
    EXPECT_EQ(state->remove_count, 1U);
    EXPECT_FALSE(state->objects.contains(test_layout().barrier_identifier));
}

TEST_F(BarrierOwnershipTest, ReleaseDoesNotRemoveForeignBarrier) {
    state->physical_hash_mismatch_identifier = test_layout().barrier_identifier;

    ASSERT_TRUE(protocol::release_registration(barrier));
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_TRUE(state->objects.contains(test_layout().barrier_identifier));
}

TEST(BarrierOwnershipControl, AmbiguousAppliedPutDoesNotAdmitWriter) {
    auto workspace =
        kasumi::test::make_temp_workspace("barrier-ambiguous-put");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->physical_hash_supported = true;
    state->put_then_fail_identifier = test_layout().barrier_identifier;
    state->put_then_fail_code = kasumi::transport::ErrorCode::Timeout;

    const auto barrier = protocol::establish_barrier(
        storage, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(barrier.has_value());
    EXPECT_TRUE(state->objects.contains(test_layout().barrier_identifier));

    const auto writer = protocol::register_writer(
        storage, test_layout(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(writer.has_value());
    ASSERT_TRUE(state->objects.contains(test_layout().barrier_identifier));
}

TEST_F(BarrierOwnershipTest, ReleaseMissingBarrierSucceedsWithoutRemove) {
    state->objects.erase(test_layout().barrier_identifier);
    state->physical_hashes.erase(test_layout().barrier_identifier);

    ASSERT_TRUE(protocol::release_registration(barrier));
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST_F(BarrierOwnershipTest, ReleaseTransportErrorDoesNotRemoveBarrier) {
    state->physical_hash_failure = kasumi::transport::ErrorCode::Timeout;

    const auto released = protocol::release_registration(barrier);
    ASSERT_FALSE(released.has_value());
    EXPECT_EQ(released.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_TRUE(state->objects.contains(test_layout().barrier_identifier));
}

TEST_F(BarrierOwnershipTest, ReleaseUnsupportedHashFallsBackToReadback) {
    state->physical_hash_unsupported_identifier =
        test_layout().barrier_identifier;
    ASSERT_TRUE(protocol::release_registration(barrier));
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 1U);
    EXPECT_EQ(state->remove_count, 1U);
    EXPECT_FALSE(state->objects.contains(test_layout().barrier_identifier));
}

TEST_F(BarrierOwnershipTest, ReleaseUnsupportedHashPreservesForeignBarrier) {
    state->physical_hash_unsupported_identifier =
        test_layout().barrier_identifier;
    replace_barrier_bytes();

    ASSERT_TRUE(protocol::release_registration(barrier));
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 1U);
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_TRUE(state->objects.contains(test_layout().barrier_identifier));
}

TEST(IntegrityMaintenanceTest, WriterPhysicalHashSuccessAvoidsReadback) {
    auto workspace = kasumi::test::make_temp_workspace("writer-hash-success");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;

    auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;
    EXPECT_EQ(state->put_count, 1U);
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
    ASSERT_TRUE(protocol::release_registration(*writer));
}

TEST(IntegrityMaintenanceTest, WriterPhysicalHashMismatchFailsWithoutReadback) {
    auto workspace = kasumi::test::make_temp_workspace("writer-hash-mismatch");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->physical_hash_mismatch = true;

    const auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::VerificationFailure);
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
}

TEST(IntegrityMaintenanceTest,
     WriterPhysicalHashUnsupportedFallsBackToReadback) {
    auto workspace = kasumi::test::make_temp_workspace("writer-hash-fallback");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 1U);
    ASSERT_TRUE(protocol::release_registration(*writer));
}

TEST(IntegrityMaintenanceTest,
     WriterPhysicalHashTransportFailureDoesNotReadback) {
    auto workspace = kasumi::test::make_temp_workspace("writer-hash-error");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->physical_hash_failure = kasumi::transport::ErrorCode::Io;

    const auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
}

TEST(IntegrityMaintenanceTest,
     WriterAdmissionFallbackPreservesListBeforeBarrierOrder) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-fallback");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->publish_barrier_after_writer_list = true;

    const auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::Blocked);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(IntegrityMaintenanceTest, WriterAdmissionAllowsSecondWriter) {
    auto workspace = kasumi::test::make_temp_workspace("writer-admission-peer");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->objects[test_layout().writers_prefix +
                   "/11111111111111111111111111111111.writer"] = {};

    auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
    ASSERT_TRUE(protocol::release_registration(*writer));
}

TEST(IntegrityMaintenanceTest, WriterAdmissionBatchRejectsMissingWriter) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-missing");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->hide_writer_listing = true;

    const auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::BackendUnsafe);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(IntegrityMaintenanceTest, WriterAdmissionBlocksPresentBarrier) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-barrier");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->objects[test_layout().barrier_identifier] = {};

    const auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::Blocked);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(IntegrityMaintenanceTest, WriterAdmissionResumesAfterBarrierRelease) {
    auto storage = make_local_storage();
    const auto root = kasumi::test::workspace_root(storage.workspace);
    auto barrier =
        protocol::establish_barrier(storage.transport, test_layout(), root);
    ASSERT_TRUE(barrier.has_value()) << barrier.error().detail;

    const auto blocked =
        protocol::register_writer(storage.transport, test_layout(), root);
    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(blocked.error().code, protocol::ErrorCode::Blocked);

    ASSERT_TRUE(protocol::release_registration(*barrier));
    auto writer =
        protocol::register_writer(storage.transport, test_layout(), root);
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;
    ASSERT_TRUE(protocol::release_registration(*writer));
}

TEST(IntegrityMaintenanceTest,
     WriterAdmissionBlocksBarrierEstablishedAfterWriterList) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-racing-barrier");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->publish_barrier_after_writer_list = true;

    const auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::Blocked);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(IntegrityMaintenanceTest,
     WriterAdmissionListFailureFailsClosedBeforeBarrierRead) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-list-error");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->fail_writer_list = true;

    const auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 0U);
}

TEST(IntegrityMaintenanceTest, WriterAdmissionBarrierFailureFailsClosed) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-barrier-error");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->fail_barrier_presence = true;

    const auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(IntegrityMaintenanceTest, WriterAdmissionBatchFailureDoesNotRetryReads) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-batch-error");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_failure = kasumi::transport::ErrorCode::Io;

    const auto writer = protocol::register_writer(
        transport, test_layout(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 0U);
    EXPECT_EQ(state->presence_count, 0U);
}

TEST(IntegrityMaintenanceTest,
     FsckProfilingRecordsCountersAndPreservesIntegrityFailures) {
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    const auto alpha_published =
        publish_remote(storage.transport, storage.workspace, alpha);
    const auto alpha_content =
        put_content(storage.transport, storage.workspace, "alpha", "alpha");

    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(checked.has_value()) << checked.error().detail;
    EXPECT_EQ(checked->checked_objects, 1U);

    EXPECT_GT(kasumi::platform::perf_trace::get_time("fsck.total_duration_us"),
              0U);
    EXPECT_GT(kasumi::platform::perf_trace::get_time(
                  "fsck.collect_storage_state_duration_us"),
              0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_time(
                  "fsck.physical_listing_duration_us"),
              0U);
    EXPECT_GT(
        kasumi::platform::perf_trace::get_time("fsck.local_tree_duration_us"),
        0U);
    EXPECT_GT(kasumi::platform::perf_trace::get_time(
                  "fsck.inventory_analysis_duration_us"),
              0U);
    EXPECT_GT(kasumi::platform::perf_trace::get_time(
                  "fsck.referenced_audit_duration_us"),
              0U);

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("fsck.audit_objects"),
              1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("fsck.audit_get_calls"),
              1U);
    EXPECT_GT(
        kasumi::platform::perf_trace::get_time("fsck.audit_get_duration_us"),
        0U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("fsck.audit_decrypt_calls"),
        1U);
    EXPECT_GT(kasumi::platform::perf_trace::get_time(
                  "fsck.audit_decrypt_duration_us"),
              0U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("fsck.audit_verify_calls"), 1U);
    EXPECT_GT(
        kasumi::platform::perf_trace::get_time("fsck.audit_verify_duration_us"),
        0U);
    EXPECT_GT(kasumi::platform::perf_trace::get_count(
                  "fsck.encrypted_bytes_downloaded"),
              0U);
    EXPECT_GT(kasumi::platform::perf_trace::get_count(
                  "fsck.plaintext_bytes_verified"),
              0U);

    // Reachability audit does not audit payloads in fsck
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("reachability.audit_objects"),
        0U);

    // Corrupt the content payload and ensure fsck fails closed
    const auto content_file =
        kasumi::test::workspace_path(storage.workspace, "storage") /
        alpha_content;
    ASSERT_TRUE(std::filesystem::exists(content_file));
    std::filesystem::resize_file(content_file, 0);

    const auto corrupt_checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key());
    ASSERT_FALSE(corrupt_checked.has_value());
    EXPECT_EQ(corrupt_checked.error().code,
              kasumi::application::integrity::ErrorCode::Unrecoverable);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

struct AuditProbeState {
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t active = 0;
    std::size_t peak_active = 0;
    std::size_t get_count = 0;
    std::size_t list_count = 0;
    std::size_t barrier_target = 0;
    std::string gate_small_identifier;
    std::string gate_medium_identifier;
    std::size_t progress_completions = 0;
    std::optional<std::size_t> fail_ordinal;
    kasumi::transport::ErrorCode fail_code = kasumi::transport::ErrorCode::Io;
    std::map<std::string, kasumi::transport::ErrorCode> failures_by_identifier;
    std::string wait_for_failure_identifier;
    std::string signal_failure_identifier;
    bool waiting_get_entered = false;
    bool failure_signaled = false;
};

struct AuditProbeTransportState {
    kasumi::transport::Transport* base = nullptr;
    AuditProbeState* probe = nullptr;
};

kasumi::transport::Result
audit_probe_get(void* context,
                std::string_view identifier,
                const std::filesystem::path& destination) {
    auto* state = static_cast<AuditProbeTransportState*>(context);
    auto* probe = state->probe;
    if (probe == nullptr || identifier.find('/') != std::string_view::npos) {
        return kasumi::transport::get(*state->base, identifier, destination);
    }

    std::size_t ordinal = 0;
    {
        std::unique_lock lock(probe->mutex);
        ordinal = probe->get_count++;
        ++probe->active;
        probe->peak_active = std::max(probe->peak_active, probe->active);
        probe->changed.notify_all();
        if (identifier == probe->wait_for_failure_identifier) {
            probe->waiting_get_entered = true;
            probe->changed.notify_all();
            probe->changed.wait(lock, [&] {
                return probe->failure_signaled;
            });
        }
        const auto gate_completion_count =
            identifier == probe->gate_small_identifier ? 2U : 1U;
        if (identifier == probe->gate_small_identifier ||
            identifier == probe->gate_medium_identifier) {
            if (!probe->changed.wait_for(lock, std::chrono::seconds{5}, [&] {
                    return probe->progress_completions >= gate_completion_count;
                })) {
                --probe->active;
                lock.unlock();
                probe->changed.notify_all();
                return std::unexpected(kasumi::transport::Error{
                    .code = kasumi::transport::ErrorCode::Timeout,
                    .message = "ordered progress gate timed out"});
            }
        }
        if (probe->barrier_target > 0 && ordinal < probe->barrier_target) {
            probe->changed.wait_until(lock,
                                      std::chrono::steady_clock::now() +
                                          std::chrono::milliseconds{300},
                                      [&] {
                                          return probe->get_count >=
                                                 probe->barrier_target;
                                      });
        }
    }

    const auto failure =
        probe->failures_by_identifier.find(std::string{identifier});
    const bool fail = failure != probe->failures_by_identifier.end() ||
                      (probe->fail_ordinal && *probe->fail_ordinal == ordinal);
    const auto error_code = failure != probe->failures_by_identifier.end()
                                ? failure->second
                                : probe->fail_code;
    auto result =
        fail ? kasumi::transport::Result{std::unexpect,
                                         kasumi::transport::Error{
                                             .code = error_code,
                                             .message =
                                                 "injected get failure for " +
                                                 std::string{identifier}}}
             : kasumi::transport::get(*state->base, identifier, destination);

    if (fail && identifier == probe->signal_failure_identifier) {
        {
            std::lock_guard lock(probe->mutex);
            probe->failure_signaled = true;
        }
        probe->changed.notify_all();
    }

    {
        std::lock_guard lock(probe->mutex);
        --probe->active;
    }
    probe->changed.notify_all();
    return result;
}

kasumi::transport::Transport
make_audit_probe_transport(AuditProbeTransportState& state,
                           kasumi::transport::Transport& base,
                           AuditProbeState& probe) {
    state.base = &base;
    state.probe = &probe;
    kasumi::transport::Transport result;
    result.state = {&state, [](void*) noexcept {
                    }};
    result.storage.initialize = [](void* ctx) {
        return kasumi::transport::initialize(
            *static_cast<AuditProbeTransportState*>(ctx)->base);
    };
    result.storage.put =
        [](void* ctx, const std::filesystem::path& src, std::string_view id) {
            return kasumi::transport::put(
                *static_cast<AuditProbeTransportState*>(ctx)->base, src, id);
        };
    result.storage.get = audit_probe_get;
    result.storage.presence = [](void* ctx, std::string_view id) {
        return kasumi::transport::presence(
            *static_cast<AuditProbeTransportState*>(ctx)->base, id);
    };
    result.storage.list = [](void* ctx) {
        auto* transport_state = static_cast<AuditProbeTransportState*>(ctx);
        if (transport_state->probe != nullptr) {
            std::lock_guard lock(transport_state->probe->mutex);
            ++transport_state->probe->list_count;
        }
        return kasumi::transport::list(*transport_state->base);
    };
    result.storage.list_prefix = [](void* ctx, std::string_view pfx) {
        return kasumi::transport::list(
            *static_cast<AuditProbeTransportState*>(ctx)->base, pfx);
    };
    result.storage.remove = [](void* ctx, std::string_view id) {
        return kasumi::transport::remove(
            *static_cast<AuditProbeTransportState*>(ctx)->base, id);
    };
    return result;
}

std::vector<std::string> setup_multi_file_dataset(
    LocalStorage& storage,
    const std::vector<std::pair<std::string, std::string>>& files) {
    kasumi::Snapshot tree;
    tree.rows.push_back(kasumi::NodeRow{
        .path = "", .hash = {}, .size = 0, .mtime = {}, .is_directory = true});
    for (const auto& [path, content] : files) {
        tree.rows.push_back(
            kasumi::NodeRow{.path = path,
                            .hash = kasumi::hasher::hash_string(content),
                            .size = content.size(),
                            .mtime = {},
                            .is_directory = false});
    }
    kasumi::finalize_snapshot(tree);
    auto commit = kasumi::history::make_commit(0, {}, tree).value();
    publish_remote(storage.transport, storage.workspace, commit);

    std::vector<std::string> identifiers;
    identifiers.reserve(files.size());
    for (const auto& [path, content] : files) {
        identifiers.push_back(
            put_content(storage.transport, storage.workspace, content, path));
    }
    return identifiers;
}

TEST(IntegrityMaintenanceTest, FsckProgressCountsUniqueReferencedObjects) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    std::vector<std::pair<std::string, std::string>> files;
    for (std::size_t i = 0; i < 100; ++i) {
        files.emplace_back("file_" + std::to_string(i),
                           "payload_" + std::to_string(i % 10));
    }
    (void)setup_multi_file_dataset(storage, files);

    std::vector<kasumi::application::FsckProgress> events;
    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key(), 4, [&](const auto& progress) {
            events.push_back(progress);
        });
    ASSERT_TRUE(checked.has_value()) << (checked ? "" : checked.error().detail);

    const auto audit =
        std::find_if(events.begin(), events.end(), [](const auto& event) {
            return event.stage ==
                   kasumi::application::FsckStage::AuditingContent;
        });
    ASSERT_NE(audit, events.end());
    EXPECT_EQ(audit->completed_objects, 0U);
    EXPECT_EQ(audit->total_objects, 10U);
    EXPECT_EQ(audit->completed_plaintext_bytes, 0U);
    EXPECT_EQ(audit->total_plaintext_bytes, 90U);
    EXPECT_EQ(events.back().stage, kasumi::application::FsckStage::Finalizing);
    EXPECT_EQ(events.back().completed_objects, 10U);
    EXPECT_EQ(events.back().completed_plaintext_bytes, 90U);
    EXPECT_EQ(events.front().stage, kasumi::application::FsckStage::Observing);
    EXPECT_FALSE(events.front().total_objects.has_value());
    EXPECT_EQ(events[1].stage, kasumi::application::FsckStage::Analyzing);
    EXPECT_FALSE(events[1].total_objects.has_value());
    std::size_t previous_objects = 0;
    std::uint64_t previous_bytes = 0;
    for (const auto& event : events) {
        EXPECT_GE(event.completed_objects, previous_objects);
        previous_objects = event.completed_objects;
        ASSERT_TRUE(event.completed_plaintext_bytes.has_value());
        EXPECT_GE(*event.completed_plaintext_bytes, previous_bytes);
        previous_bytes = *event.completed_plaintext_bytes;
    }
}

TEST(IntegrityMaintenanceTest, FsckProgressByteTotalsBecomeUnknownOnOverflow) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    kasumi::Snapshot tree;
    tree.rows.push_back(kasumi::NodeRow{
        .path = "", .hash = {}, .size = 0, .mtime = {}, .is_directory = true});
    tree.rows.push_back(
        kasumi::NodeRow{.path = "huge.bin",
                        .hash = kasumi::hasher::hash_string("huge"),
                        .size = std::numeric_limits<std::uint64_t>::max(),
                        .mtime = {},
                        .is_directory = false});
    tree.rows.push_back(
        kasumi::NodeRow{.path = "one.bin",
                        .hash = kasumi::hasher::hash_string("one"),
                        .size = 1,
                        .mtime = {},
                        .is_directory = false});
    kasumi::finalize_snapshot(tree);
    auto commit = kasumi::history::make_commit(0, {}, tree).value();
    publish_remote(storage.transport, storage.workspace, commit);

    std::vector<kasumi::application::FsckProgress> events;
    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key(), 2, [&](const auto& progress) {
            events.push_back(progress);
        });
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::Unrecoverable);
    ASSERT_FALSE(events.empty());
    const auto audit =
        std::find_if(events.begin(), events.end(), [](const auto& event) {
            return event.stage ==
                   kasumi::application::FsckStage::AuditingContent;
        });
    ASSERT_NE(audit, events.end());
    EXPECT_EQ(audit->total_objects, 2U);
    EXPECT_FALSE(audit->total_plaintext_bytes.has_value());
    EXPECT_EQ(events.back().completed_objects, 2U);
    EXPECT_FALSE(events.back().completed_plaintext_bytes.has_value());
}

TEST(IntegrityMaintenanceTest,
     FsckProgressByteTotalsFollowOutOfOrderCompletions) {
    constexpr std::size_t small_size = 1024;
    constexpr std::size_t medium_size = 16 * 1024;
    constexpr std::size_t large_size = 1024 * 1024;
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    const auto identifiers = setup_multi_file_dataset(
        storage,
        {
            {"a-small.bin", std::string(small_size, 'a')},
            {"b-large.bin", std::string(large_size, 'b')},
            {"c-medium.bin", std::string(medium_size, 'c')},
        });
    AuditProbeState probe;
    probe.gate_small_identifier = identifiers[0];
    probe.gate_medium_identifier = identifiers[2];
    AuditProbeTransportState probe_state;
    auto wrapped_transport =
        make_audit_probe_transport(probe_state, storage.transport, probe);
    const auto calling_thread = std::this_thread::get_id();
    std::vector<std::uint64_t> completed_byte_totals;
    std::mutex completed_byte_totals_mutex;
    std::atomic_bool callback_on_calling_thread{true};
    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key(), 3, [&](const auto& progress) {
            if (std::this_thread::get_id() != calling_thread) {
                callback_on_calling_thread.store(false);
            }
            if (progress.stage !=
                    kasumi::application::FsckStage::AuditingContent ||
                progress.completed_objects == 0) {
                return;
            }
            ASSERT_TRUE(progress.completed_plaintext_bytes.has_value());
            {
                std::lock_guard lock(completed_byte_totals_mutex);
                completed_byte_totals.push_back(
                    *progress.completed_plaintext_bytes);
            }
            {
                std::lock_guard lock(probe.mutex);
                probe.progress_completions = progress.completed_objects;
            }
            probe.changed.notify_all();
        });
    ASSERT_TRUE(checked.has_value()) << (checked ? "" : checked.error().detail);
    EXPECT_TRUE(callback_on_calling_thread.load());
    ASSERT_EQ(completed_byte_totals.size(), 3U);
    EXPECT_EQ(completed_byte_totals[0], large_size);
    EXPECT_EQ(completed_byte_totals[1], large_size + medium_size);
    EXPECT_EQ(completed_byte_totals[2], large_size + medium_size + small_size);
}

TEST(IntegrityMaintenanceTest,
     FsckProgressCallbackPreservesRequestsAndConcurrency) {
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    (void)setup_multi_file_dataset(storage,
                                   {
                                       {"f0.txt", "payload_0"},
                                       {"f1.txt", "payload_1"},
                                       {"f2.txt", "payload_2"},
                                       {"f3.txt", "payload_3"},
                                   });

    AuditProbeState plain_probe;
    plain_probe.barrier_target = 4;
    AuditProbeTransportState plain_state;
    auto plain_transport =
        make_audit_probe_transport(plain_state, storage.transport, plain_probe);
    const auto plain = kasumi::application::integrity::fsck(
        runtime, plain_transport, test_key(), 4);
    ASSERT_TRUE(plain.has_value());
    const auto plain_gets =
        kasumi::platform::perf_trace::get_count("fsck.audit_get_calls");
    const auto plain_decrypts =
        kasumi::platform::perf_trace::get_count("fsck.audit_decrypt_calls");
    const auto plain_verifies =
        kasumi::platform::perf_trace::get_count("fsck.audit_verify_calls");
    const auto plain_lists =
        kasumi::platform::perf_trace::get_count("history.full_list_calls");

    kasumi::platform::perf_trace::reset();
    AuditProbeState progress_probe;
    progress_probe.barrier_target = 4;
    AuditProbeTransportState progress_state;
    auto progress_transport = make_audit_probe_transport(
        progress_state, storage.transport, progress_probe);
    std::size_t event_count = 0;
    const auto with_progress = kasumi::application::integrity::fsck(
        runtime, progress_transport, test_key(), 4, [&](const auto&) {
            ++event_count;
        });
    ASSERT_TRUE(with_progress.has_value());

    EXPECT_EQ(with_progress->checked_objects, plain->checked_objects);
    EXPECT_EQ(plain_probe.get_count, progress_probe.get_count);
    EXPECT_EQ(plain_probe.get_count, 4U);
    EXPECT_EQ(plain_probe.list_count, 1U);
    EXPECT_EQ(progress_probe.list_count, 1U);
    EXPECT_EQ(plain_probe.peak_active, 4U);
    EXPECT_EQ(progress_probe.peak_active, 4U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("fsck.audit_get_calls"),
              plain_gets);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("fsck.audit_decrypt_calls"),
        plain_decrypts);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("fsck.audit_verify_calls"),
        plain_verifies);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("history.full_list_calls"),
        plain_lists);
    EXPECT_GT(event_count, 0U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTest,
     FsckProgressCallbackExceptionsDoNotChangeResult) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    (void)setup_multi_file_dataset(storage, {{"file.txt", "payload"}});

    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key(), 1, [](const auto&) {
            throw std::runtime_error("display failed");
        });
    ASSERT_TRUE(checked.has_value()) << (checked ? "" : checked.error().detail);
    EXPECT_EQ(checked->checked_objects, 1U);
}

TEST(IntegrityMaintenanceTest, FsckProgressDoesNotRequirePerfTracing) {
    kasumi::platform::perf_trace::force_enable(false);
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    (void)setup_multi_file_dataset(storage, {{"file.txt", "payload"}});
    std::vector<kasumi::application::FsckProgress> events;

    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key(), 1, [&](const auto& progress) {
            events.push_back(progress);
        });
    ASSERT_TRUE(checked.has_value());
    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events.back().stage, kasumi::application::FsckStage::Finalizing);
    EXPECT_EQ(events.back().completed_objects, 1U);
    EXPECT_EQ(events.back().total_objects, 1U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTest,
     FsckProgressCountsMissingAndCorruptAsCompletedWork) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    const auto identifiers =
        setup_multi_file_dataset(storage,
                                 {
                                     {"healthy.txt", "h"},
                                     {"missing.txt", "miss"},
                                     {"corrupt.txt", "corrupt"},
                                 });
    std::filesystem::remove(
        kasumi::test::workspace_path(storage.workspace, "storage") /
        identifiers[1]);
    std::filesystem::resize_file(
        kasumi::test::workspace_path(storage.workspace, "storage") /
            identifiers[2],
        0);

    std::vector<kasumi::application::FsckProgress> events;
    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key(), 3, [&](const auto& progress) {
            events.push_back(progress);
        });
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::Unrecoverable);

    ASSERT_FALSE(events.empty());
    const auto& final = events.back();
    EXPECT_EQ(final.stage, kasumi::application::FsckStage::Finalizing);
    EXPECT_EQ(final.total_objects, 3U);
    EXPECT_EQ(final.completed_objects, 3U);
    EXPECT_EQ(final.total_plaintext_bytes, 12U);
    EXPECT_EQ(final.completed_plaintext_bytes, 12U);
}

TEST(IntegrityMaintenanceTest, FsckHardFailureDoesNotFakeCompleteProgress) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    (void)setup_multi_file_dataset(storage,
                                   {
                                       {"f0.txt", "payload_0"},
                                       {"f1.txt", "payload_1"},
                                       {"f2.txt", "payload_2"},
                                       {"f3.txt", "payload_3"},
                                   });
    AuditProbeState probe;
    probe.fail_ordinal = 1;
    probe.fail_code = kasumi::transport::ErrorCode::PermissionDenied;
    AuditProbeTransportState probe_state;
    auto wrapped_transport =
        make_audit_probe_transport(probe_state, storage.transport, probe);
    std::vector<kasumi::application::FsckProgress> events;

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key(), 4, [&](const auto& progress) {
            events.push_back(progress);
        });
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::TransportFailure);
    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events.back().stage, kasumi::application::FsckStage::Finalizing);
    EXPECT_LT(events.back().completed_objects, *events.back().total_objects);
}

TEST(IntegrityMaintenanceTest, BoundedConcurrentFsckAuditsWithPeakInFlight) {
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    setup_multi_file_dataset(storage,
                             {
                                 {"f0.txt", "payload_0"},
                                 {"f1.txt", "payload_1"},
                                 {"f2.txt", "payload_2"},
                                 {"f3.txt", "payload_3"},
                             });

    AuditProbeState probe;
    probe.barrier_target = 4;
    AuditProbeTransportState probe_state;
    auto wrapped_transport =
        make_audit_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key(), 4);
    ASSERT_TRUE(checked.has_value()) << (checked ? "" : checked.error().detail);
    EXPECT_EQ(checked->checked_objects, 4U);
    EXPECT_EQ(probe.peak_active, 4U);
    EXPECT_LE(probe.peak_active, 4U);
    EXPECT_EQ(probe.get_count, 4U);

    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("fsck.audit_peak_in_flight"),
        4U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTest,
     BoundedConcurrentFsckLimitsInFlightWhenConcurrencyLessThanF) {
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    setup_multi_file_dataset(storage,
                             {
                                 {"f0.txt", "payload_0"},
                                 {"f1.txt", "payload_1"},
                                 {"f2.txt", "payload_2"},
                                 {"f3.txt", "payload_3"},
                                 {"f4.txt", "payload_4"},
                                 {"f5.txt", "payload_5"},
                             });

    AuditProbeState probe;
    probe.barrier_target = 2;
    AuditProbeTransportState probe_state;
    auto wrapped_transport =
        make_audit_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key(), 2);
    ASSERT_TRUE(checked.has_value()) << (checked ? "" : checked.error().detail);
    EXPECT_EQ(checked->checked_objects, 6U);
    EXPECT_EQ(probe.peak_active, 2U);
    EXPECT_LE(probe.peak_active, 2U);
    EXPECT_EQ(probe.get_count, 6U);

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("fsck.audit_objects"),
              6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("fsck.audit_get_calls"),
              6U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("fsck.audit_decrypt_calls"),
        6U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("fsck.audit_verify_calls"), 6U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("fsck.audit_completion_count"),
        6U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTest,
     BoundedConcurrentFsckLimitsWorkersWhenFLessThanConcurrency) {
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    setup_multi_file_dataset(storage,
                             {
                                 {"f0.txt", "payload_0"},
                                 {"f1.txt", "payload_1"},
                                 {"f2.txt", "payload_2"},
                             });

    AuditProbeState probe;
    probe.barrier_target = 3;
    AuditProbeTransportState probe_state;
    auto wrapped_transport =
        make_audit_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key(), 8);
    ASSERT_TRUE(checked.has_value()) << (checked ? "" : checked.error().detail);
    EXPECT_EQ(checked->checked_objects, 3U);
    EXPECT_EQ(probe.peak_active, 3U);
    EXPECT_LE(probe.peak_active, 3U);
    EXPECT_EQ(probe.get_count, 3U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("fsck.audit_completion_count"),
        3U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTest,
     BoundedConcurrentFsckConcurrencyOneMatchesSerial) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    setup_multi_file_dataset(storage,
                             {
                                 {"f0.txt", "payload_0"},
                                 {"f1.txt", "payload_1"},
                                 {"f2.txt", "payload_2"},
                                 {"f3.txt", "payload_3"},
                             });

    AuditProbeState probe;
    probe.barrier_target = 0;
    AuditProbeTransportState probe_state;
    auto wrapped_transport =
        make_audit_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key(), 1);
    ASSERT_TRUE(checked.has_value()) << (checked ? "" : checked.error().detail);
    EXPECT_EQ(checked->checked_objects, 4U);
    EXPECT_EQ(probe.peak_active, 1U);
    EXPECT_EQ(probe.get_count, 4U);
}

TEST(IntegrityMaintenanceTest,
     BoundedConcurrentFsckCollectsAllMissingObjectsDeterministically) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto ids = setup_multi_file_dataset(storage,
                                              {
                                                  {"f0.txt", "payload_0"},
                                                  {"f1.txt", "payload_1"},
                                                  {"f2.txt", "payload_2"},
                                                  {"f3.txt", "payload_3"},
                                              });

    const auto content_file_1 =
        kasumi::test::workspace_path(storage.workspace, "storage") / ids[1];
    const auto content_file_3 =
        kasumi::test::workspace_path(storage.workspace, "storage") / ids[3];
    std::filesystem::remove(content_file_1);
    std::filesystem::remove(content_file_3);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key(), 4);
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::Unrecoverable);
    EXPECT_NE(checked.error().detail.find("f1.txt"), std::string::npos);
    EXPECT_NE(checked.error().detail.find("f3.txt"), std::string::npos);
}

TEST(IntegrityMaintenanceTest, BoundedConcurrentFsckRejectsCorruptCiphertext) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto ids = setup_multi_file_dataset(storage,
                                              {
                                                  {"f0.txt", "payload_0"},
                                                  {"f1.txt", "payload_1"},
                                                  {"f2.txt", "payload_2"},
                                                  {"f3.txt", "payload_3"},
                                              });

    const auto content_file_2 =
        kasumi::test::workspace_path(storage.workspace, "storage") / ids[2];
    std::filesystem::resize_file(content_file_2, 0);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key(), 4);
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::Unrecoverable);
    EXPECT_NE(checked.error().detail.find("f2.txt"), std::string::npos);
}

TEST(IntegrityMaintenanceTest,
     BoundedConcurrentFsckRejectsValidAeadWrongLogicalIdentity) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto ids = setup_multi_file_dataset(storage,
                                              {
                                                  {"f0.txt", "payload_0"},
                                                  {"f1.txt", "payload_1"},
                                              });

    const auto bogus_plain =
        kasumi::test::workspace_path(storage.workspace, "bogus.plain");
    const auto content_file_1 =
        kasumi::test::workspace_path(storage.workspace, "storage") / ids[1];
    kasumi::test::write_text(bogus_plain, "bogus_payload_1");
    ASSERT_TRUE(
        kasumi::crypto::encrypt_file(bogus_plain, content_file_1, test_key()));

    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key(), 2);
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::Unrecoverable);
    EXPECT_NE(checked.error().detail.find("f1.txt"), std::string::npos);
}

TEST(IntegrityMaintenanceTest,
     BoundedConcurrentFsckHardTransportFailureDrainsAndReportsLowestIndex) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const std::vector<std::pair<std::string, std::string>> files{
        {"f0.txt", "payload_0"},
        {"f1.txt", "payload_1"},
    };
    const auto identifiers = setup_multi_file_dataset(storage, files);
    std::vector<std::pair<std::string, std::string>> logical_order;
    for (std::size_t i = 0; i < files.size(); ++i) {
        logical_order.emplace_back(
            kasumi::hash_hex(kasumi::hasher::hash_string(files[i].second)),
            identifiers[i]);
    }
    std::ranges::sort(logical_order);

    AuditProbeState probe;
    const auto& lower_index_id = logical_order.front().second;
    const auto& lower_index_hash = logical_order.front().first;
    const auto& higher_index_id = logical_order.back().second;
    probe.failures_by_identifier.emplace(
        lower_index_id, kasumi::transport::ErrorCode::PermissionDenied);
    probe.failures_by_identifier.emplace(higher_index_id,
                                         kasumi::transport::ErrorCode::Io);
    probe.wait_for_failure_identifier = lower_index_id;
    probe.signal_failure_identifier = higher_index_id;
    AuditProbeTransportState probe_state;
    auto wrapped_transport =
        make_audit_probe_transport(probe_state, storage.transport, probe);
    kasumi::application::integrity::testing::FsckWorkerEventCallback
        worker_event = [&](auto event, std::size_t index) {
            if (event == kasumi::application::integrity::testing::
                             FsckWorkerEvent::BeforeAudit &&
                index == 1) {
                std::unique_lock lock(probe.mutex);
                probe.changed.wait(lock, [&] {
                    return probe.waiting_get_entered;
                });
            }
        };

    const auto checked =
        kasumi::application::integrity::testing::fsck_with_worker_events(
            runtime,
            wrapped_transport,
            test_key(),
            2,
            {},
            std::move(worker_event));
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::TransportFailure);
    EXPECT_EQ(checked.error().object_identifier, lower_index_hash);
    EXPECT_NE(checked.error().detail.find("injected get failure for " +
                                          lower_index_id),
              std::string::npos);
    EXPECT_TRUE(probe.failure_signaled);
}

TEST(IntegrityMaintenanceTest,
     BoundedConcurrentFsckInternalStopDoesNotMaskCausalTransportFailure) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    const std::vector<std::pair<std::string, std::string>> files{
        {"f0.txt", "payload_0"},
        {"f1.txt", "payload_1"},
    };
    const auto identifiers = setup_multi_file_dataset(storage, files);
    std::vector<std::pair<std::string, std::string>> logical_order;
    for (std::size_t i = 0; i < files.size(); ++i) {
        logical_order.emplace_back(
            kasumi::hash_hex(kasumi::hasher::hash_string(files[i].second)),
            identifiers[i]);
    }
    std::ranges::sort(logical_order);

    AuditProbeState probe;
    const auto& higher_index_id = logical_order.back().second;
    const auto& higher_index_hash = logical_order.back().first;
    probe.failures_by_identifier.emplace(
        higher_index_id, kasumi::transport::ErrorCode::PermissionDenied);
    AuditProbeTransportState probe_state;
    auto wrapped_transport =
        make_audit_probe_transport(probe_state, storage.transport, probe);
    std::mutex gate_mutex;
    std::condition_variable gate_changed;
    bool lower_worker_waiting = false;
    bool window_stop_requested = false;
    bool lower_worker_observed_stop = false;
    std::vector<kasumi::application::FsckProgress> events;
    kasumi::application::integrity::testing::FsckWorkerEventCallback
        worker_event = [&](auto event, std::size_t index) {
            using Event =
                kasumi::application::integrity::testing::FsckWorkerEvent;
            if (event == Event::BeforeAudit && index == 0) {
                std::unique_lock lock(gate_mutex);
                lower_worker_waiting = true;
                gate_changed.notify_all();
                gate_changed.wait(lock, [&] {
                    return window_stop_requested;
                });
                lower_worker_observed_stop = true;
            } else if (event == Event::BeforeAudit && index == 1) {
                std::unique_lock lock(gate_mutex);
                gate_changed.wait(lock, [&] {
                    return lower_worker_waiting;
                });
            } else if (event == Event::WindowStopRequested) {
                {
                    std::lock_guard lock(gate_mutex);
                    window_stop_requested = true;
                }
                gate_changed.notify_all();
            }
        };

    const auto checked =
        kasumi::application::integrity::testing::fsck_with_worker_events(
            runtime,
            wrapped_transport,
            test_key(),
            2,
            [&](const auto& progress) {
                events.push_back(progress);
            },
            std::move(worker_event));
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::TransportFailure);
    EXPECT_EQ(checked.error().object_identifier, higher_index_hash);
    EXPECT_NE(checked.error().detail.find("injected get failure for " +
                                          higher_index_id),
              std::string::npos);
    EXPECT_TRUE(lower_worker_observed_stop);
    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events.back().stage, kasumi::application::FsckStage::Finalizing);
    ASSERT_TRUE(events.back().total_objects.has_value());
    EXPECT_LT(events.back().completed_objects, *events.back().total_objects);
}

TEST(IntegrityMaintenanceTest,
     BoundedConcurrentFsckCancellationStopsWorkAndCleansWorkspace) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const std::vector<std::pair<std::string, std::string>> files{
        {"f0.txt", "payload_0"},
        {"f1.txt", "payload_1"},
        {"f2.txt", "payload_2"},
        {"f3.txt", "payload_3"},
    };
    const auto identifiers = setup_multi_file_dataset(storage, files);

    AuditProbeState probe;
    std::vector<std::pair<std::string, std::string>> ordered_ids;
    for (std::size_t i = 0; i < files.size(); ++i) {
        ordered_ids.emplace_back(
            kasumi::hash_hex(kasumi::hasher::hash_string(files[i].second)),
            identifiers[i]);
    }
    std::ranges::sort(ordered_ids);
    probe.gate_medium_identifier = ordered_ids[1].second;
    AuditProbeTransportState probe_state;
    auto wrapped_transport =
        make_audit_probe_transport(probe_state, storage.transport, probe);
    std::vector<kasumi::application::FsckProgress> events;

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key(), 2, [&](const auto& progress) {
            events.push_back(progress);
            if (progress.stage ==
                    kasumi::application::FsckStage::AuditingContent &&
                progress.completed_objects == 1) {
                {
                    std::lock_guard lock(probe.mutex);
                    probe.progress_completions = 1;
                }
                probe.changed.notify_all();
                kasumi::platform::cancellation::request();
            }
        });
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::StateFailure);
    EXPECT_TRUE(kasumi::platform::cancellation::requested());
    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events.back().stage, kasumi::application::FsckStage::Finalizing);
    EXPECT_LT(events.back().completed_objects, *events.back().total_objects);
    kasumi::platform::cancellation::reset();
}

struct SnapshotProbeState {
    std::size_t list_calls = 0;
    std::function<void(std::size_t call_index)> on_list_finish;
};

struct SnapshotProbeTransportState {
    kasumi::transport::Transport* base = nullptr;
    SnapshotProbeState* probe = nullptr;
};

kasumi::transport::Transport
make_snapshot_probe_transport(SnapshotProbeTransportState& state,
                              kasumi::transport::Transport& base,
                              SnapshotProbeState& probe) {
    state.base = &base;
    state.probe = &probe;
    kasumi::transport::Transport result;
    result.state = {&state, [](void*) noexcept {
                    }};
    result.storage.initialize = [](void* ctx) {
        return kasumi::transport::initialize(
            *static_cast<SnapshotProbeTransportState*>(ctx)->base);
    };
    result.storage.put =
        [](void* ctx, const std::filesystem::path& src, std::string_view id) {
            return kasumi::transport::put(
                *static_cast<SnapshotProbeTransportState*>(ctx)->base, src, id);
        };
    result.storage.get =
        [](void* ctx, std::string_view id, const std::filesystem::path& dst) {
            return kasumi::transport::get(
                *static_cast<SnapshotProbeTransportState*>(ctx)->base, id, dst);
        };
    result.storage.presence = [](void* ctx, std::string_view id) {
        return kasumi::transport::presence(
            *static_cast<SnapshotProbeTransportState*>(ctx)->base, id);
    };
    result.storage.list = [](void* ctx) {
        auto* st = static_cast<SnapshotProbeTransportState*>(ctx);
        const auto idx = ++st->probe->list_calls;
        auto res = kasumi::transport::list(*st->base);
        if (st->probe->on_list_finish) {
            st->probe->on_list_finish(idx);
        }
        return res;
    };
    result.storage.list_prefix = [](void* ctx, std::string_view pfx) {
        return kasumi::transport::list(
            *static_cast<SnapshotProbeTransportState*>(ctx)->base, pfx);
    };
    result.storage.remove = [](void* ctx, std::string_view id) {
        return kasumi::transport::remove(
            *static_cast<SnapshotProbeTransportState*>(ctx)->base, id);
    };
    return result;
}

TEST(IntegrityMaintenanceTest,
     SnapshotCharacterizationUnknownObjectBeforeFirstListFailsClosed) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(storage.transport, storage.workspace, alpha);
    put_content(storage.transport, storage.workspace, "alpha", "alpha");

    const auto storage_root =
        kasumi::test::workspace_path(storage.workspace, "storage");
    std::filesystem::create_directories(storage_root / "foreign");
    {
        std::ofstream out(storage_root / "foreign" / "intruder.txt");
        out << "foreign payload";
    }

    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key());
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::IntegrityFailure);
    EXPECT_NE(checked.error().detail.find("foreign/intruder.txt"),
              std::string::npos);
}

TEST(IntegrityMaintenanceTest,
     SnapshotSemanticsIgnoresForeignObjectInjectedAfterFirstList) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(storage.transport, storage.workspace, alpha);
    put_content(storage.transport, storage.workspace, "alpha", "alpha");

    const auto storage_root =
        kasumi::test::workspace_path(storage.workspace, "storage");

    SnapshotProbeState probe;
    probe.on_list_finish = [&](std::size_t call_index) {
        if (call_index == 1) {
            std::filesystem::create_directories(storage_root / "foreign");
            std::ofstream out(storage_root / "foreign" / "intruder.txt");
            out << "foreign payload";
        }
    };
    SnapshotProbeTransportState probe_state;
    auto wrapped_transport =
        make_snapshot_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key());
    EXPECT_EQ(probe.list_calls, 1U);
    ASSERT_TRUE(checked.has_value()) << checked.error().detail;
}

TEST(
    IntegrityMaintenanceTest,
    SnapshotCharacterizationCanonicalContentAppearingBetweenListsPassesValidationWithoutAlteringInventory) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(storage.transport, storage.workspace, alpha);
    put_content(storage.transport, storage.workspace, "alpha", "alpha");

    const auto storage_root =
        kasumi::test::workspace_path(storage.workspace, "storage");
    const std::string concurrent_content_hash(64, 'e');

    SnapshotProbeState probe;
    probe.on_list_finish = [&](std::size_t call_index) {
        if (call_index == 1) {
            std::ofstream out(storage_root / concurrent_content_hash);
            out << "concurrently added valid canonical hash object";
        }
    };
    SnapshotProbeTransportState probe_state;
    auto wrapped_transport =
        make_snapshot_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key());
    EXPECT_EQ(probe.list_calls, 1U);
    ASSERT_TRUE(checked.has_value()) << checked.error().detail;
    EXPECT_EQ(checked->checked_objects, 1U);
}

TEST(
    IntegrityMaintenanceTest,
    SnapshotCharacterizationReferencedContentDeletedAfterFirstListFailsClosedOnPayloadAudit) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(storage.transport, storage.workspace, alpha);
    const auto alpha_content =
        put_content(storage.transport, storage.workspace, "alpha", "alpha");

    const auto storage_root =
        kasumi::test::workspace_path(storage.workspace, "storage");
    const auto content_path = storage_root / alpha_content;

    SnapshotProbeState probe;
    probe.on_list_finish = [&](std::size_t call_index) {
        if (call_index == 1) {
            std::error_code ec;
            std::filesystem::remove(content_path, ec);
        }
    };
    SnapshotProbeTransportState probe_state;
    auto wrapped_transport =
        make_snapshot_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key());
    EXPECT_EQ(probe.list_calls, 1U);
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::Unrecoverable);
    EXPECT_NE(
        checked.error().detail.find("referenced objects missing or corrupted"),
        std::string::npos);
}

TEST(
    IntegrityMaintenanceTest,
    SnapshotCharacterizationReferencedContentCorruptedAfterFirstListFailsClosedOnPayloadAudit) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(storage.transport, storage.workspace, alpha);
    const auto alpha_content =
        put_content(storage.transport, storage.workspace, "alpha", "alpha");

    const auto storage_root =
        kasumi::test::workspace_path(storage.workspace, "storage");
    const auto content_path = storage_root / alpha_content;

    SnapshotProbeState probe;
    probe.on_list_finish = [&](std::size_t call_index) {
        if (call_index == 1) {
            std::error_code ec;
            std::filesystem::resize_file(content_path, 0, ec);
        }
    };
    SnapshotProbeTransportState probe_state;
    auto wrapped_transport =
        make_snapshot_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key());
    EXPECT_EQ(probe.list_calls, 1U);
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::Unrecoverable);
}

TEST(IntegrityMaintenanceTest, HealthyFsckPerformsExactlyOnePhysicalListCall) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(storage.transport, storage.workspace, alpha);
    put_content(storage.transport, storage.workspace, "alpha", "alpha");

    SnapshotProbeState probe;
    SnapshotProbeTransportState probe_state;
    auto wrapped_transport =
        make_snapshot_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key());
    ASSERT_TRUE(checked.has_value()) << checked.error().detail;
    EXPECT_EQ(probe.list_calls, 1U);
}

TEST(IntegrityMaintenanceTest,
     UnknownPhysicalIdentifierInSingleObservedSnapshotFailsClosed) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(storage.transport, storage.workspace, alpha);
    put_content(storage.transport, storage.workspace, "alpha", "alpha");

    const auto storage_root =
        kasumi::test::workspace_path(storage.workspace, "storage");
    std::filesystem::create_directories(storage_root / "foreign");
    {
        std::ofstream out(storage_root / "foreign" / "intruder.txt");
        out << "foreign payload";
    }

    SnapshotProbeState probe;
    SnapshotProbeTransportState probe_state;
    auto wrapped_transport =
        make_snapshot_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key());
    ASSERT_FALSE(checked.has_value());
    EXPECT_EQ(checked.error().code, IntegrityErrorCode::IntegrityFailure);
    EXPECT_NE(checked.error().detail.find("foreign/intruder.txt"),
              std::string::npos);
    EXPECT_EQ(probe.list_calls, 1U);
}

TEST(IntegrityMaintenanceTest,
     FsckUsesExactlyTheFirstObservedSnapshotWithoutSecondListing) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(storage.transport, storage.workspace, alpha);
    put_content(storage.transport, storage.workspace, "alpha", "alpha");

    const auto storage_root =
        kasumi::test::workspace_path(storage.workspace, "storage");

    SnapshotProbeState probe;
    probe.on_list_finish = [&](std::size_t call_index) {
        if (call_index == 1) {
            std::filesystem::create_directories(storage_root / "foreign");
            std::ofstream out(storage_root / "foreign" / "intruder.txt");
            out << "foreign payload";
        }
    };
    SnapshotProbeTransportState probe_state;
    auto wrapped_transport =
        make_snapshot_probe_transport(probe_state, storage.transport, probe);

    const auto checked = kasumi::application::integrity::fsck(
        runtime, wrapped_transport, test_key());
    EXPECT_EQ(probe.list_calls, 1U);
    ASSERT_TRUE(checked.has_value()) << checked.error().detail;
}

TEST(IntegrityMaintenanceTest,
     PerfTraceEnabledVsDisabledProducesIdenticalFsckResultAndInvariants) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    const auto pub_alpha =
        publish_remote(storage.transport, storage.workspace, alpha);
    put_content(storage.transport, storage.workspace, "alpha", "alpha");

    const std::vector<std::string> parents{pub_alpha.head.commit_id};
    const auto beta = make_commit(1, parents, "beta.txt", "beta").value();
    publish_remote(storage.transport, storage.workspace, beta);
    put_content(storage.transport, storage.workspace, "beta", "beta");

    kasumi::platform::perf_trace::force_enable(false);
    kasumi::platform::perf_trace::reset();
    const auto checked_disabled = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(checked_disabled.has_value())
        << checked_disabled.error().detail;

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    const auto checked_enabled = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(checked_enabled.has_value()) << checked_enabled.error().detail;

    EXPECT_EQ(checked_disabled->checked_objects,
              checked_enabled->checked_objects);
    EXPECT_EQ(checked_disabled->repaired_objects,
              checked_enabled->repaired_objects);

    EXPECT_GE(
        kasumi::platform::perf_trace::get_count("history.full_list_calls"), 1U);
    EXPECT_GE(
        kasumi::platform::perf_trace::get_count("marker.variants_observed"),
        1U);
    EXPECT_GE(
        kasumi::platform::perf_trace::get_count("commit.variants_observed"),
        2U);
    EXPECT_GE(
        kasumi::platform::perf_trace::get_count("history.reachable_commits"),
        2U);
    EXPECT_GE(
        kasumi::platform::perf_trace::get_count("content.physical_objects"),
        2U);
    EXPECT_GE(kasumi::platform::perf_trace::get_count("content.referenced_ids"),
              2U);

    kasumi::platform::perf_trace::force_enable(false);
    kasumi::platform::perf_trace::reset();
}

} // namespace
