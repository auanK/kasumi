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

TEST(MaintenanceProtocolPayloadTest, FormatProducesExactExpectedBytesAcrossKindsAndTokens) {
    const std::vector<std::pair<std::string, std::string>> test_cases = {
        {"writer", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        {"barrier", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"},
        {"probe", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"},
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
        EXPECT_EQ(actual, expected)
            << "Mismatch for kind: '" << kind << "' and token: '" << token << "'";
    }
}

} // namespace
