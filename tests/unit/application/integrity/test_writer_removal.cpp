#include "application/execute.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/profile.hpp"
#include "kasumi/test/history_storage.hpp"
#include "platform/profile_lock.hpp"

namespace {

namespace protocol = kasumi::application::history_storage::maintenance_protocol;
namespace application = kasumi::application;

TEST(WriterRemovalContract, InvalidAndForeignIdentifiersNeverMutateStorage) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = application::history_storage::derive_remote_layout(test_key());
    auto foreign_key = test_key();
    foreign_key[0] ^= 0xff;
    const auto foreign = application::history_storage::derive_remote_layout(foreign_key);
    const std::vector<std::string> identifiers{
        "", layout.barrier_identifier,
        layout.writers_prefix + "invalid",
        foreign.writers_prefix + std::string(32, 'a')};
    for (const auto& identifier : identifiers) {
        state->objects[identifier] = {'f'};
    }
    const auto before = state->objects;
    for (const auto& identifier : identifiers) {
        const auto result = protocol::remove_writer(storage, layout, identifier);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, protocol::ErrorCode::InvalidInput);
        EXPECT_EQ(state->objects, before);
    }
    EXPECT_EQ(state->remove_count, 0U);
}

TEST(WriterRemovalContract, ExistingBarrierAndSelectedWriterRemainUntouched) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto layout = application::history_storage::derive_remote_layout(test_key());
    const auto writer = layout.writers_prefix + std::string(32, 'a');
    state->objects[writer] = {'w'};
    state->objects[layout.barrier_identifier] = {'b'};
    const auto before = state->objects;

    const auto result = protocol::remove_writer(storage, layout, writer);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, protocol::ErrorCode::Blocked);
    EXPECT_EQ(state->objects, before);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST(WriterRemovalContract, UnprovenWriterListingNeverAuthorizesRemoval) {
    for (const bool failed_listing : {false, true}) {
        FakeState* state = nullptr;
        auto storage = make_fake_transport(state);
        const auto layout = application::history_storage::derive_remote_layout(test_key());
        const auto writer = layout.writers_prefix + std::string(32, 'a');
        state->objects[writer] = {'w'};
        state->hide_writer_listing = !failed_listing;
        state->fail_writer_list = failed_listing;
        const auto before = state->objects;

        const auto result = protocol::remove_writer(storage, layout, writer);

        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(state->objects, before);
        EXPECT_EQ(state->remove_count, 0U);
    }
}

TEST(WriterRemovalContract, ProfileLockBlocksThePublicRemoveWriterOperation) {
    auto workspace = kasumi::test::make_temp_workspace("writer-removal-profile-lock");
    const application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const application::Profile profile{
        "demo", kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    ASSERT_TRUE(std::filesystem::create_directories(profile.remote_dir));
    const application::MasterKeyHex master{std::string(64, 'f')};
    ASSERT_TRUE(application::create_profile(environment, profile, master));
    auto storage = kasumi::transport::open_transport(profile.remote_dir);
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    key.fill(0xff);
    const auto layout = application::history_storage::derive_remote_layout(key);
    const auto writer = layout.writers_prefix + std::string(32, 'a');
    const auto source = kasumi::test::workspace_path(workspace, "writer.marker");
    kasumi::test::write_text(source, "writer");
    ASSERT_TRUE(kasumi::transport::put(*storage, source, writer));
    auto locked = kasumi::platform::acquire_profile_lock(
        environment.app_data_dir / "profile-demo.lock");
    ASSERT_TRUE(locked.has_value());
    auto handle = *locked;

    const auto blocked = application::execute({
        application::Request{.operation = application::Operation::RemoveWriter,
                             .profile_name = "demo", .writer_identifier = writer},
        application::Credentials{master}, environment});
    kasumi::platform::release_profile_lock(handle);

    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(blocked.error().code, application::ErrorCode::RuntimeFailure);
    EXPECT_EQ(kasumi::transport::presence(*storage, writer).value(),
              kasumi::transport::Presence::Present);
}

} // namespace
