#include "application/history_storage/epoch.hpp"
#include "core/history.hpp"
#define KASUMI_TEST_HISTORY_STORAGE_NO_ERROR_CODE_ALIAS
#include "kasumi/test/history_storage.hpp"
#undef KASUMI_TEST_HISTORY_STORAGE_NO_ERROR_CODE_ALIAS
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <string>
#include <vector>

namespace {

namespace epoch = kasumi::application::history_storage::epoch;
using epoch::Anchor;
using epoch::Epoch;
using epoch::ErrorCode;

std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> epoch_test_key() {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    for (std::size_t index = 0; index < key.size(); ++index) {
        key[index] = static_cast<std::uint8_t>(index);
    }
    return key;
}

std::string id(char digit) {
    return std::string(kasumi::HASH_HEX_SIZE, digit);
}

std::string numbered_id(std::size_t value) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string result(kasumi::HASH_HEX_SIZE, '0');
    result[result.size() - 2] = digits[(value >> 4U) & 0x0fU];
    result[result.size() - 1] = digits[value & 0x0fU];
    return result;
}

Epoch representative_epoch() {
    return Epoch{
        .vault_id = id('a'),
        .sequence = 2,
        .issued_at = 1'800'000'000,
        .policy = {.min_history_depth = 5, .min_history_age_hours = 6},
        .anchors = {{.commit_id = id('c'), .height = 40},
                    {.commit_id = id('d'), .height = 41}},
        .previous_epoch_id = id('b'),
    };
}

epoch::VerifiedEpoch verified(const Epoch& value) {
    const auto key = epoch_test_key();
    const auto sealed = epoch::seal(value, key).value();
    return epoch::open(sealed.bytes, sealed.reference, key).value();
}

std::vector<epoch::VerifiedEpoch> valid_chain(std::size_t count) {
    std::vector<epoch::VerifiedEpoch> result;
    result.reserve(count);
    std::string previous;
    for (std::size_t index = 0; index < count; ++index) {
        auto value = representative_epoch();
        value.sequence = index;
        value.issued_at += static_cast<std::int64_t>(index);
        value.previous_epoch_id = previous;
        result.push_back(verified(value));
        previous = result.back().reference.epoch_id;
    }
    return result;
}

epoch::SealedEpoch seal_from(const epoch::VerifiedEpoch& value) {
    return epoch::seal(value.value, epoch_test_key()).value();
}

void install_chain(FakeState& state,
                   std::span<const epoch::VerifiedEpoch> chain) {
    for (const auto& value : chain) {
        const auto sealed = epoch::seal(value.value, epoch_test_key()).value();
        const auto identifier = epoch::object_identifier(sealed.reference);
        ASSERT_TRUE(identifier.has_value());
        state.objects[*identifier] = sealed.bytes;
    }
}

TEST(EpochCodecTest, RoundTripsCanonicalAndAuthenticatedFormats) {
    const auto original = representative_epoch();
    const auto canonical = epoch::encode(original);
    ASSERT_TRUE(canonical.has_value());
    const auto decoded = epoch::decode(*canonical);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, original);

    const auto key = epoch_test_key();
    const auto first = epoch::seal(original, key);
    const auto second = epoch::seal(original, key);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first->reference, second->reference);
    EXPECT_EQ(first->bytes, second->bytes);

    const auto opened = epoch::open(first->bytes, first->reference, key);
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(opened->value, original);
    EXPECT_EQ(opened->reference, first->reference);
}

TEST(EpochCodecTest, UsesImmutableCanonicalObjectNames) {
    const auto sealed =
        epoch::seal(representative_epoch(), epoch_test_key()).value();
    const auto object = epoch::object_identifier(sealed.reference);
    ASSERT_TRUE(object.has_value());
    EXPECT_TRUE(object->starts_with("history/epochs/v1/00000000000000000002-"));
    EXPECT_TRUE(object->ends_with(".epoch"));

    const auto parsed = epoch::parse_object_identifier(*object);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, sealed.reference);

    auto malformed = *object;
    malformed[std::string_view{"history/epochs/v1/"}.size()] = 'x';
    EXPECT_FALSE(epoch::parse_object_identifier(malformed).has_value());
    EXPECT_FALSE(epoch::parse_object_identifier("epoch/current").has_value());
    EXPECT_FALSE(epoch::object_identifier({.sequence = 1, .epoch_id = "bad"})
                     .has_value());
}

TEST(EpochCodecTest, RejectsTamperingWrongKeyAndMismatchedNames) {
    const auto key = epoch_test_key();
    const auto sealed = epoch::seal(representative_epoch(), key).value();

    for (std::size_t index = 0; index < sealed.bytes.size(); ++index) {
        SCOPED_TRACE(index);
        auto tampered = sealed.bytes;
        tampered[index] ^= 0x01U;
        EXPECT_FALSE(epoch::open(tampered, sealed.reference, key).has_value());
    }

    auto wrong_key = key;
    wrong_key[0] ^= 0xffU;
    const auto wrong = epoch::open(sealed.bytes, sealed.reference, wrong_key);
    ASSERT_FALSE(wrong.has_value());
    EXPECT_EQ(wrong.error().code, ErrorCode::AuthenticationFailure);

    auto wrong_id = sealed.reference;
    wrong_id.epoch_id = id('f');
    const auto renamed = epoch::open(sealed.bytes, wrong_id, key);
    ASSERT_FALSE(renamed.has_value());
    EXPECT_EQ(renamed.error().code, ErrorCode::AuthenticationFailure);

    auto wrong_sequence = sealed.reference;
    ++wrong_sequence.sequence;
    const auto resequenced = epoch::open(sealed.bytes, wrong_sequence, key);
    ASSERT_FALSE(resequenced.has_value());
    EXPECT_EQ(resequenced.error().code, ErrorCode::AuthenticationFailure);
}

TEST(EpochCodecTest, SelectsLatestAndRejectsSequenceConflicts) {
    Epoch genesis = representative_epoch();
    genesis.sequence = 0;
    genesis.previous_epoch_id.clear();
    genesis.anchors.resize(1);
    const auto verified_genesis = verified(genesis);

    Epoch next = genesis;
    next.sequence = 1;
    next.issued_at += 10;
    next.previous_epoch_id = verified_genesis.reference.epoch_id;
    next.anchors.front().height = 50;
    const auto verified_next = verified(next);

    const std::vector ordered{verified_genesis, verified_next, verified_next};
    const auto latest = epoch::select_latest(ordered);
    ASSERT_TRUE(latest.has_value());
    EXPECT_EQ(*latest, verified_next);

    const std::vector reversed{verified_next, verified_genesis};
    const auto latest_reversed = epoch::select_latest(reversed);
    ASSERT_TRUE(latest_reversed.has_value());
    EXPECT_EQ(*latest_reversed, verified_next);

    Epoch conflict = next;
    ++conflict.issued_at;
    const auto verified_conflict = verified(conflict);
    const std::vector conflicting{
        verified_next, verified_genesis, verified_conflict};
    const auto rejected = epoch::select_latest(conflicting);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, ErrorCode::Conflict);

    EXPECT_EQ(epoch::select_latest({}).error().code, ErrorCode::NotFound);
}

TEST(EpochCodecTest, RequiresAnAuthenticatedContiguousChain) {
    const auto chain = valid_chain(3);

    const std::vector reordered{chain[2], chain[0], chain[1], chain[1]};
    const auto latest = epoch::select_latest(reordered);
    ASSERT_TRUE(latest.has_value());
    EXPECT_EQ(*latest, chain[2]);

    const std::vector missing_genesis{chain[2], chain[1]};
    EXPECT_EQ(epoch::select_latest(missing_genesis).error().code,
              ErrorCode::Conflict);

    const std::vector gap{chain[0], chain[2]};
    EXPECT_EQ(epoch::select_latest(gap).error().code, ErrorCode::Conflict);

    auto broken = chain[1];
    broken.value.previous_epoch_id = id('f');
    const std::vector broken_pointer{chain[0], broken};
    EXPECT_EQ(epoch::select_latest(broken_pointer).error().code,
              ErrorCode::Conflict);

    auto fork = chain[1].value;
    ++fork.issued_at;
    const auto forked = verified(fork);
    const std::vector fork_first{chain[0], chain[1], forked};
    const std::vector fork_second{forked, chain[0], chain[1]};
    EXPECT_EQ(epoch::select_latest(fork_first).error().code,
              ErrorCode::Conflict);
    EXPECT_EQ(epoch::select_latest(fork_second).error().code,
              ErrorCode::Conflict);
}

TEST(EpochCodecTest, RejectsMaxSequenceWithoutWalkingTheSequenceRange) {
    auto genesis = valid_chain(1).front();
    auto maximum = genesis.value;
    maximum.sequence = std::numeric_limits<std::uint64_t>::max();
    maximum.previous_epoch_id = id('b');
    const auto verified_maximum = verified(maximum);

    const std::vector candidates{genesis, verified_maximum};
    const auto rejected = epoch::select_latest(candidates);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, ErrorCode::Conflict);
}

TEST(EpochCodecTest, RejectsDifferentVaultsAndPolicies) {
    const auto first = verified(representative_epoch());

    auto other_vault = representative_epoch();
    other_vault.vault_id = id('e');
    const std::vector vault_conflict{first, verified(other_vault)};
    EXPECT_EQ(epoch::select_latest(vault_conflict).error().code,
              ErrorCode::Conflict);

    auto other_policy = representative_epoch();
    ++other_policy.policy.min_history_age_hours;
    const std::vector policy_conflict{first, verified(other_policy)};
    EXPECT_EQ(epoch::select_latest(policy_conflict).error().code,
              ErrorCode::Conflict);
}

TEST(EpochCodecTest, RejectsInvalidFieldsAndQuantities) {
    const auto expect_rejected = [](Epoch value, ErrorCode expected) {
        const auto encoded = epoch::encode(value);
        ASSERT_FALSE(encoded.has_value());
        EXPECT_EQ(encoded.error().code, expected);
    };

    auto value = representative_epoch();
    value.vault_id = "bad";
    expect_rejected(value, ErrorCode::InvalidInput);

    value = representative_epoch();
    value.issued_at = -1;
    expect_rejected(value, ErrorCode::InvalidInput);

    value = representative_epoch();
    value.policy.min_history_depth = 0;
    expect_rejected(value, ErrorCode::InvalidInput);

    value = representative_epoch();
    value.policy.min_history_depth =
        static_cast<std::uint32_t>(kasumi::history::maximum_graph_depth + 1);
    expect_rejected(value, ErrorCode::InvalidInput);

    value = representative_epoch();
    value.policy.min_history_age_hours = 0;
    expect_rejected(value, ErrorCode::InvalidInput);

    value = representative_epoch();
    value.anchors.clear();
    expect_rejected(value, ErrorCode::InvalidInput);

    value = representative_epoch();
    value.anchors.clear();
    for (std::size_t index = 0; index <= epoch::maximum_anchor_count; ++index) {
        value.anchors.push_back(
            Anchor{.commit_id = numbered_id(index), .height = index});
    }
    expect_rejected(value, ErrorCode::LimitExceeded);

    value = representative_epoch();
    std::ranges::reverse(value.anchors);
    expect_rejected(value, ErrorCode::InvalidInput);

    value = representative_epoch();
    value.anchors.back().commit_id = value.anchors.front().commit_id;
    expect_rejected(value, ErrorCode::InvalidInput);

    value = representative_epoch();
    value.sequence = 0;
    expect_rejected(value, ErrorCode::InvalidInput);

    value = representative_epoch();
    value.previous_epoch_id.clear();
    expect_rejected(value, ErrorCode::InvalidInput);
}

TEST(EpochCodecTest, RejectsUnsupportedTruncatedAndNonCanonicalBytes) {
    const auto canonical = epoch::encode(representative_epoch()).value();

    auto unsupported = canonical;
    unsupported[4] = 2;
    const auto version = epoch::decode(unsupported);
    ASSERT_FALSE(version.has_value());
    EXPECT_EQ(version.error().code, ErrorCode::UnsupportedVersion);

    auto trailing = canonical;
    trailing.push_back(0);
    const auto extra = epoch::decode(trailing);
    ASSERT_FALSE(extra.has_value());
    EXPECT_EQ(extra.error().code, ErrorCode::InvalidEncoding);

    auto excessive_count = canonical;
    constexpr std::size_t anchor_count_offset =
        4 + 1 + kasumi::HASH_SIZE + sizeof(std::uint64_t) +
        sizeof(std::int64_t) + 2 * sizeof(std::uint32_t) + kasumi::HASH_SIZE;
    static_assert(epoch::maximum_anchor_count < 255);
    ASSERT_LT(anchor_count_offset, excessive_count.size());
    excessive_count[anchor_count_offset] =
        static_cast<std::uint8_t>(epoch::maximum_anchor_count + 1);
    const auto too_many = epoch::decode(excessive_count);
    ASSERT_FALSE(too_many.has_value());
    EXPECT_EQ(too_many.error().code, ErrorCode::LimitExceeded);

    for (std::size_t size = 0; size < canonical.size(); ++size) {
        SCOPED_TRACE(size);
        EXPECT_FALSE(
            epoch::decode(std::span<const std::uint8_t>{canonical.data(), size})
                .has_value());
    }

    std::vector<std::uint8_t> oversized(epoch::maximum_encoded_size + 1);
    const auto too_large = epoch::decode(oversized);
    ASSERT_FALSE(too_large.has_value());
    EXPECT_EQ(too_large.error().code, ErrorCode::LimitExceeded);
}

TEST(EpochLoadByIdTest, ReturnsExactAuthenticatedEpoch) {
    auto workspace = kasumi::test::make_temp_workspace("epoch-load-by-id");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto key = epoch_test_key();
    const auto value = representative_epoch();
    const auto sealed = epoch::seal(value, key);
    ASSERT_TRUE(sealed.has_value());
    ASSERT_TRUE(epoch::publish(
        *storage, *sealed, kasumi::test::workspace_root(workspace)));

    const auto loaded =
        epoch::load_by_id(*storage,
                          key,
                          kasumi::test::workspace_root(workspace),
                          sealed->reference.epoch_id);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    const auto opened = epoch::open(sealed->bytes, sealed->reference, key);
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(**loaded, *opened);
}

TEST(EpochLoadChainTest, ReturnsEveryAuthenticatedEpochInSequence) {
    auto workspace = kasumi::test::make_temp_workspace("epoch-load-chain");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const auto expected = valid_chain(3);
    for (const auto& value : expected) {
        const auto sealed = seal_from(value);
        ASSERT_TRUE(epoch::publish(
            *storage, sealed, kasumi::test::workspace_root(workspace)));
    }

    const auto loaded = epoch::load_chain(
        *storage, epoch_test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(*loaded, expected);
}

TEST(EpochLoadChainTest, ReusesObservedIdentifiersWithoutRelisting) {
    auto workspace =
        kasumi::test::make_temp_workspace("epoch-load-chain-observed");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const auto expected = valid_chain(3);
    for (const auto& value : expected) {
        const auto sealed = seal_from(value);
        ASSERT_TRUE(epoch::publish(
            *storage, sealed, kasumi::test::workspace_root(workspace)));
    }
    const auto identifiers = kasumi::transport::list(*storage);
    ASSERT_TRUE(identifiers.has_value());

    const epoch::Reference late_reference{.sequence = 3, .epoch_id = id('f')};
    const auto late_identifier = epoch::object_identifier(late_reference);
    ASSERT_TRUE(late_identifier.has_value());
    kasumi::test::write_text(storage_path /
                                 std::filesystem::path{*late_identifier},
                             "Epoch publicado depois da fotografia");

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    const auto loaded =
        epoch::load_chain(*storage,
                          epoch_test_key(),
                          kasumi::test::workspace_root(workspace),
                          *identifiers);
    const auto full_lists =
        kasumi::platform::perf_trace::get_count("transport list");
    const auto prefix_lists =
        kasumi::platform::perf_trace::get_count("transport list prefix");
    kasumi::platform::perf_trace::force_enable(false);

    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(*loaded, expected);
    EXPECT_EQ(full_lists, 0U);
    EXPECT_EQ(prefix_lists, 0U);
}

TEST(EpochLoadByIdTest, ReturnsEmptyWhenAbsent) {
    auto workspace = kasumi::test::make_temp_workspace("epoch-load-absent");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto loaded =
        epoch::load_by_id(*storage,
                          epoch_test_key(),
                          kasumi::test::workspace_root(workspace),
                          id('f'));
    ASSERT_TRUE(loaded.has_value());
    EXPECT_FALSE(*loaded);
}

TEST(EpochLoadByIdTest, RejectsTamperedEpoch) {
    auto workspace = kasumi::test::make_temp_workspace("epoch-load-tampered");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto key = epoch_test_key();
    const auto sealed = epoch::seal(representative_epoch(), key);
    ASSERT_TRUE(sealed.has_value());
    ASSERT_TRUE(epoch::publish(
        *storage, *sealed, kasumi::test::workspace_root(workspace)));
    const auto identifier = epoch::object_identifier(sealed->reference).value();
    auto bytes = kasumi::test::read_binary(storage_path /
                                           std::filesystem::path{identifier});
    ASSERT_FALSE(bytes.empty());
    bytes.back() ^= std::byte{0x01};
    kasumi::test::write_binary(
        storage_path / std::filesystem::path{identifier}, bytes);

    const auto loaded =
        epoch::load_by_id(*storage,
                          key,
                          kasumi::test::workspace_root(workspace),
                          sealed->reference.epoch_id);
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, ErrorCode::AuthenticationFailure);
}

TEST(EpochLoadByIdTest, DoesNotSubstituteDifferentLatestEpoch) {
    auto workspace = kasumi::test::make_temp_workspace("epoch-load-exact");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto key = epoch_test_key();
    auto first = representative_epoch();
    first.sequence = 1;
    first.previous_epoch_id = id('b');
    auto second = first;
    second.sequence = 2;
    second.previous_epoch_id = id('c');
    const auto sealed_first = epoch::seal(first, key);
    const auto sealed_second = epoch::seal(second, key);
    ASSERT_TRUE(sealed_first.has_value());
    ASSERT_TRUE(sealed_second.has_value());
    ASSERT_TRUE(epoch::publish(
        *storage, *sealed_first, kasumi::test::workspace_root(workspace)));
    ASSERT_TRUE(epoch::publish(
        *storage, *sealed_second, kasumi::test::workspace_root(workspace)));

    const auto loaded =
        epoch::load_by_id(*storage,
                          key,
                          kasumi::test::workspace_root(workspace),
                          sealed_first->reference.epoch_id);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((**loaded).reference, sealed_first->reference);
}

TEST(EpochLoadByIdTest, RejectsMultipleReferencesForSameId) {
    auto workspace = kasumi::test::make_temp_workspace("epoch-load-conflict");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto key = epoch_test_key();
    const auto sealed = epoch::seal(representative_epoch(), key);
    ASSERT_TRUE(sealed.has_value());
    ASSERT_TRUE(epoch::publish(
        *storage, *sealed, kasumi::test::workspace_root(workspace)));
    const auto conflicting =
        std::string{"history/epochs/v1/00000000000000000003-"} +
        sealed->reference.epoch_id + ".epoch";
    const auto source = kasumi::test::workspace_path(workspace, "copy.epoch");
    kasumi::test::write_binary(
        source,
        std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(sealed->bytes.data()),
            sealed->bytes.size()});
    ASSERT_TRUE(kasumi::transport::put(*storage, source, conflicting));

    const auto loaded =
        epoch::load_by_id(*storage,
                          key,
                          kasumi::test::workspace_root(workspace),
                          sealed->reference.epoch_id);
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, ErrorCode::Conflict);
}

TEST(EpochLoadLatestTest,
     RejectsMissingHistoricalEpochInsteadOfReturningNewer) {
    auto workspace = kasumi::test::make_temp_workspace("epoch-load-chain-gap");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto chain = valid_chain(3);
    ASSERT_TRUE(epoch::publish(*storage,
                               seal_from(chain[0]),
                               kasumi::test::workspace_root(workspace)));
    ASSERT_TRUE(epoch::publish(*storage,
                               seal_from(chain[2]),
                               kasumi::test::workspace_root(workspace)));

    const auto latest = epoch::load_latest(
        *storage, epoch_test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(latest.has_value());
    EXPECT_EQ(latest.error().code, ErrorCode::Conflict);
}

TEST(EpochLoadLatestTest, RejectsBrokenHistoricalPointer) {
    auto workspace =
        kasumi::test::make_temp_workspace("epoch-load-broken-pointer");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto chain = valid_chain(2);
    auto broken = chain[1].value;
    broken.previous_epoch_id = id('f');
    const auto broken_sealed = epoch::seal(broken, epoch_test_key());
    ASSERT_TRUE(broken_sealed.has_value());
    ASSERT_TRUE(epoch::publish(*storage,
                               seal_from(chain[0]),
                               kasumi::test::workspace_root(workspace)));
    ASSERT_TRUE(epoch::publish(
        *storage, *broken_sealed, kasumi::test::workspace_root(workspace)));

    const auto latest = epoch::load_latest(
        *storage, epoch_test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(latest.has_value());
    EXPECT_EQ(latest.error().code, ErrorCode::Conflict);
}

TEST(EpochLoadLatestTest, SupportsMoreThan1024HistoricalEpochs) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    auto workspace = kasumi::test::make_temp_workspace("epoch-large-chain");
    const auto chain = valid_chain(1500);
    install_chain(*state, chain);

    const auto loaded = epoch::load_latest(
        storage, epoch_test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((**loaded).reference, chain.back().reference);
    EXPECT_EQ(state->get_count, chain.size());
}

TEST(EpochLoadByIdTest, LargeInventoryGetsOnlyTheExactEpoch) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    auto workspace = kasumi::test::make_temp_workspace("epoch-large-lookup");
    const auto chain = valid_chain(1500);
    install_chain(*state, chain);

    const auto loaded =
        epoch::load_by_id(storage,
                          epoch_test_key(),
                          kasumi::test::workspace_root(workspace),
                          chain[1200].reference.epoch_id);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((**loaded).reference, chain[1200].reference);
    EXPECT_EQ(state->get_count, 1U);
}

TEST(EpochLoadLatestTest, KnownCheckpointAuthenticationIsDeltaBound) {
    for (const auto count : {std::size_t{20}, std::size_t{1500}}) {
        FakeState* state = nullptr;
        auto storage = make_fake_transport(state);
        auto workspace = kasumi::test::make_temp_workspace("epoch-delta-chain");
        const auto chain = valid_chain(count);
        install_chain(*state, chain);

        const auto accepted = chain[count - 4].reference;
        const auto loaded =
            epoch::load_latest(storage,
                               epoch_test_key(),
                               kasumi::test::workspace_root(workspace),
                               std::optional<epoch::Reference>{accepted});
        ASSERT_TRUE(loaded.has_value() && *loaded);
        EXPECT_EQ((**loaded).reference, chain.back().reference);
        EXPECT_EQ(state->get_count, 4U);
    }
}

TEST(EpochLoadLatestTest, NoopCheckpointAuthenticatesOnlyLatest) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    auto workspace = kasumi::test::make_temp_workspace("epoch-noop");
    const auto chain = valid_chain(20);
    install_chain(*state, chain);

    const auto loaded = epoch::load_latest(
        storage,
        epoch_test_key(),
        kasumi::test::workspace_root(workspace),
        std::optional<epoch::Reference>{chain.back().reference});
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ(state->get_count, 1U);
}

TEST(EpochLoadLatestTest, TofuStillAuthenticatesTheCompleteChain) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    auto workspace = kasumi::test::make_temp_workspace("epoch-tofu");
    const auto chain = valid_chain(6);
    install_chain(*state, chain);

    const auto loaded = epoch::load_latest(
        storage, epoch_test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ(state->get_count, chain.size());
}

TEST(EpochLoadLatestTest, CheckpointRequiresExactEpochId) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    auto workspace = kasumi::test::make_temp_workspace("epoch-checkpoint-id");
    const auto base = valid_chain(5);
    install_chain(*state, std::span{base}.first(2));

    auto alternate = base[2].value;
    ++alternate.issued_at;
    alternate.previous_epoch_id = base[1].reference.epoch_id;
    auto current = verified(alternate);
    {
        const auto sealed = seal_from(current);
        const auto identifier = epoch::object_identifier(sealed.reference);
        ASSERT_TRUE(identifier.has_value());
        state->objects[*identifier] = sealed.bytes;
    }
    for (std::size_t sequence = 3; sequence < base.size(); ++sequence) {
        auto next = base[sequence].value;
        next.previous_epoch_id = current.reference.epoch_id;
        current = verified(next);
        const auto sealed = seal_from(current);
        const auto identifier = epoch::object_identifier(sealed.reference);
        ASSERT_TRUE(identifier.has_value());
        state->objects[*identifier] = sealed.bytes;
    }

    const auto loaded =
        epoch::load_latest(storage,
                           epoch_test_key(),
                           kasumi::test::workspace_root(workspace),
                           std::optional<epoch::Reference>{base[2].reference});
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, ErrorCode::Conflict);
}

TEST(EpochLoadLatestTest, CollapsesExactDuplicateInventoryEntries) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    auto workspace = kasumi::test::make_temp_workspace("epoch-duplicate-list");
    const auto chain = valid_chain(2);
    install_chain(*state, chain);
    const auto first = epoch::object_identifier(chain[0].reference).value();
    const auto second = epoch::object_identifier(chain[1].reference).value();
    const std::vector identifiers{first, second, second};

    const auto loaded =
        epoch::load_latest(storage,
                           epoch_test_key(),
                           kasumi::test::workspace_root(workspace),
                           identifiers);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ(state->get_count, 2U);
}

TEST(EpochLoadLatestTest, RejectsConflictingInventoryReferences) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    auto workspace = kasumi::test::make_temp_workspace("epoch-conflict-list");
    const auto chain = valid_chain(2);
    const auto alternate_value = [&] {
        auto value = chain[1].value;
        ++value.issued_at;
        return value;
    }();
    const auto alternate = verified(alternate_value);
    const auto first = epoch::object_identifier(chain[0].reference).value();
    const auto second = epoch::object_identifier(chain[1].reference).value();
    const auto fork = epoch::object_identifier(alternate.reference).value();
    const std::vector fork_identifiers{first, second, fork};
    const auto same_id_different_sequence =
        epoch::object_identifier(
            {.sequence = 2, .epoch_id = chain[0].reference.epoch_id})
            .value();

    auto fork_result =
        epoch::load_latest(storage,
                           epoch_test_key(),
                           kasumi::test::workspace_root(workspace),
                           fork_identifiers);
    ASSERT_FALSE(fork_result.has_value());
    EXPECT_EQ(fork_result.error().code, ErrorCode::Conflict);

    const std::vector reused_id{first, same_id_different_sequence};
    auto reused_id_result =
        epoch::load_latest(storage,
                           epoch_test_key(),
                           kasumi::test::workspace_root(workspace),
                           reused_id);
    ASSERT_FALSE(reused_id_result.has_value());
    EXPECT_EQ(reused_id_result.error().code, ErrorCode::Conflict);
}

} // namespace
