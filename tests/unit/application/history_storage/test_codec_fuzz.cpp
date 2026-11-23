#include "application/history_storage/activity.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/history_storage.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/node.hpp"
#include "core/operation.hpp"
#include "core/transaction/codec.hpp"
#include "core/transaction/types.hpp"
#include "core/wire.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/pack.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t default_iterations = 20'000;
constexpr std::size_t maximum_iterations = 10'000'000;
constexpr std::size_t maximum_input_size = 4'096;

std::uint64_t random_value(std::uint64_t& state) noexcept {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
}

std::size_t random_index(std::uint64_t& state, std::size_t limit) noexcept {
    return static_cast<std::size_t>(random_value(state) % limit);
}

std::size_t iteration_count() noexcept {
    const char* setting = std::getenv("KASUMI_FUZZ_ITERATIONS");
    if (setting == nullptr) {
        return default_iterations;
    }
    std::size_t value = 0;
    const std::string_view text{setting};
    const auto parsed =
        std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} &&
                   parsed.ptr == text.data() + text.size() && value > 0U &&
                   value <= maximum_iterations
               ? value
               : default_iterations;
}

std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> test_master_key() noexcept {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(0x30U + i);
    }
    return key;
}

std::vector<std::uint8_t> make_kpak_plaintext_seed() {
    struct Item {
        kasumi::Hash hash{};
        std::string payload;
    };
    std::array<Item, 2> items{
        Item{kasumi::hasher::hash_string("alpha-member"), "alpha-member"},
        Item{kasumi::hasher::hash_string("beta-member"), "beta-member"},
    };
    std::ranges::sort(items, {}, &Item::hash);

    constexpr std::size_t header_size = 9;
    constexpr std::size_t entry_size = kasumi::HASH_SIZE + 8U;
    std::size_t payload_total = 0;
    for (const auto& item : items) {
        payload_total += item.payload.size();
    }

    std::vector<std::uint8_t> buffer(
        header_size + items.size() * entry_size + payload_total);
    buffer[0] = 'K';
    buffer[1] = 'P';
    buffer[2] = 'A';
    buffer[3] = 'K';
    buffer[4] = 1U;
    wire::encode_le<std::uint32_t>(
        static_cast<std::uint32_t>(items.size()), buffer.data() + 5U);

    std::uint32_t payload_offset = 0;
    const std::size_t data_base = header_size + items.size() * entry_size;
    for (std::size_t i = 0; i < items.size(); ++i) {
        const auto size = static_cast<std::uint32_t>(items[i].payload.size());
        std::uint8_t* entry = buffer.data() + header_size + i * entry_size;
        std::memcpy(entry, items[i].hash.data(), kasumi::HASH_SIZE);
        wire::encode_le<std::uint32_t>(payload_offset,
                                               entry + kasumi::HASH_SIZE);
        wire::encode_le<std::uint32_t>(size,
                                               entry + kasumi::HASH_SIZE + 4U);
        std::memcpy(buffer.data() + data_base + payload_offset,
                    items[i].payload.data(),
                    size);
        payload_offset += size;
    }
    return buffer;
}

std::vector<std::uint8_t> make_kcom_manifest_seed() {
    const std::string small_payload = "hello-pack-member";
    const auto small_hash = kasumi::hasher::hash_string(small_payload);
    std::vector<kasumi::crypto::pack::PackMemberDescriptor> desc{
        {.hash = small_hash,
         .size = static_cast<std::uint32_t>(small_payload.size())},
    };
    const auto pack_hash = kasumi::crypto::pack::compute_pack_hash(desc).value();

    const auto large_hash = kasumi::hasher::hash_string("large-chunked-file");
    const auto c1_hash = kasumi::hasher::hash_string("chunk-1");
    const auto c2_hash = kasumi::hasher::hash_string("chunk-2");

    kasumi::Snapshot tree{
        .rows =
            {
                kasumi::NodeRow{
                    .path = "",
                    .hash = {},
                    .size = 0,
                    .mtime = 1'700'000'000'000'000'000LL,
                    .is_directory = true,
                },
                kasumi::NodeRow{
                    .path = "big.bin",
                    .hash = large_hash,
                    .size = 9'000'000ULL,
                    .mtime = 1'700'000'000'000'000'000LL,
                    .is_directory = false,
                },
                kasumi::NodeRow{
                    .path = "small.txt",
                    .hash = small_hash,
                    .size = small_payload.size(),
                    .mtime = 1'700'000'000'000'000'000LL,
                    .is_directory = false,
                },
            },
    };
    kasumi::finalize_snapshot(tree);

    kasumi::history::StorageManifest manifest{
        .packed_blobs =
            {
                kasumi::history::PackedBlobEntry{
                    .blob_hash = small_hash,
                    .size = small_payload.size(),
                    .pack_hash = pack_hash,
                },
            },
        .chunked_files =
            {
                kasumi::history::ChunkedFileEntry{
                    .file_hash = large_hash,
                    .file_size = 9'000'000ULL,
                    .chunks =
                        {
                            {.hash = c1_hash, .size = 4'500'000U},
                            {.hash = c2_hash, .size = 4'500'000U},
                        },
                },
            },
    };

    kasumi::history::Commit commit{
        .height = 1,
        .created_at = 1'700'000'000LL,
        .parents = {std::string(64, '0')},
        .tree = std::move(tree),
        .storage = std::move(manifest),
        .authorship =
            {
                .operation = kasumi::history::CommitOriginOperation::Sync,
                .machine_id = {1, 2, 3, 4},
                .machine_name = "fuzz-node",
            },
    };
    return kasumi::history::serialize(commit).value();
}

void mutate(std::vector<std::uint8_t>& bytes, std::uint64_t& state) {
    const auto edit_count = 1U + random_index(state, 8U);
    for (std::size_t edit = 0; edit < edit_count; ++edit) {
        switch (random_index(state, 7U)) {
            case 0:
                if (bytes.size() < maximum_input_size) {
                    bytes.insert(
                        bytes.begin() +
                            static_cast<std::ptrdiff_t>(
                                random_index(state, bytes.size() + 1U)),
                        static_cast<std::uint8_t>(random_value(state)));
                }
                break;
            case 1:
                if (!bytes.empty()) {
                    bytes.erase(bytes.begin() +
                                static_cast<std::ptrdiff_t>(
                                    random_index(state, bytes.size())));
                }
                break;
            case 2:
                if (!bytes.empty()) {
                    bytes[random_index(state, bytes.size())] ^=
                        static_cast<std::uint8_t>(random_value(state));
                }
                break;
            case 3:
                bytes.resize(random_index(state, maximum_input_size + 1U),
                             static_cast<std::uint8_t>(random_value(state)));
                break;
            case 4:
                if (bytes.size() > 1U) {
                    std::swap(bytes[random_index(state, bytes.size())],
                              bytes[random_index(state, bytes.size())]);
                }
                break;
            case 5:
                if (!bytes.empty()) {
                    // Boundary truncation inside headers and payload frames.
                    bytes.resize(random_index(
                        state, std::min<std::size_t>(bytes.size(), 64U) + 1U));
                }
                break;
            default:
                if (!bytes.empty()) {
                    static constexpr std::array<std::uint8_t, 4> extreme{
                        0x00U, 0x7FU, 0x80U, 0xFFU};
                    bytes[random_index(state, bytes.size())] =
                        extreme[random_index(state, extreme.size())];
                }
                break;
        }
    }
}

struct SeedCorpus {
    std::vector<std::uint8_t> kcom_bootstrap;
    std::vector<std::uint8_t> kcom_manifest;
    std::vector<std::uint8_t> marker;
    std::vector<std::uint8_t> transaction;
    std::vector<std::uint8_t> kpak_plaintext;
    std::vector<std::uint8_t> kact_plaintext;
    std::vector<std::uint8_t> epoch_plaintext;
    std::vector<std::uint8_t> epoch_sealed;
    std::vector<std::uint8_t> aead_content;
    std::vector<std::uint8_t> aead_pack;
    kasumi::application::history_storage::epoch::Reference epoch_ref;
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key;
};

SeedCorpus build_corpus() {
    const auto key = test_master_key();
    const auto bootstrap = kasumi::history::make_empty_bootstrap().value();
    const auto encoded_bootstrap = kasumi::history::serialize(bootstrap).value();
    auto encoded_manifest = make_kcom_manifest_seed();

    const auto marker = kasumi::application::history_storage::encode_marker(
                            {.commit_id = std::string(64, 'a'),
                             .ciphertext_id = std::string(64, 'b')})
                            .value();

    const auto plan = kasumi::make_sync_plan(
        {kasumi::Operation{.action = kasumi::Action::Download,
                           .path = "file.txt",
                           .hash = std::string(64, 'd'),
                           .alt_path = {},
                           .size = 4,
                           .exclusive_destination = false}},
        7);
    const auto record =
        kasumi::transaction::make_record(
            std::string(32, '1'), 1, 7, plan, false, std::string(64, 'c'))
            .value();
    const auto encoded_record =
        kasumi::transaction::codec::encode(record).value();
    std::vector<std::uint8_t> transaction(encoded_record.size());
    std::ranges::transform(encoded_record, transaction.begin(), [](auto byte) {
        return static_cast<std::uint8_t>(byte);
    });

    auto kpak_plain = make_kpak_plaintext_seed();

    const kasumi::application::history_storage::activity::ActivityRecord act{
        .event_id = std::string(32, 'a'),
        .operation = kasumi::application::history_storage::activity::
            ActivityOperation::GarbageCollect,
        .outcome = kasumi::application::history_storage::activity::
            ActivityOutcome::Succeeded,
        .machine_id = {9, 8, 7, 6},
        .machine_name = "fuzz-node",
        .started_at = 1'700'000'000LL,
        .finished_at = 1'700'000'005LL,
        .duration_ms = 5'000ULL,
        .metric_primary = 3ULL,
        .metric_secondary = 1ULL,
        .metric_bytes = 4'096ULL,
        .flags = kasumi::application::history_storage::activity::
            flag_analysis_only,
        .stage = "analyzing",
        .detail = "ok",
    };
    auto kact_plain =
        kasumi::application::history_storage::activity::encode(act).value();

    const kasumi::application::history_storage::epoch::Epoch epoch{
        .vault_id = std::string(64, 'e'),
        .sequence = 0,
        .issued_at = 1'700'000'000LL,
        .policy = {.min_history_depth = 5U, .min_history_age_hours = 6U},
        .anchors = {{.commit_id = std::string(64, '1'), .height = 1}},
        .previous_epoch_id = {},
    };
    auto epoch_plain =
        kasumi::application::history_storage::epoch::encode(epoch).value();
    auto sealed =
        kasumi::application::history_storage::epoch::seal(epoch, key).value();

    const std::string payload = "protocol-v3-seed-payload";
    const std::span<const std::uint8_t> payload_span{
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size()};
    auto aead_content = kasumi::crypto::encrypt_bytes(
                            payload_span, key, kasumi::crypto::FilePurpose::Content)
                            .value();
    auto aead_pack = kasumi::crypto::encrypt_bytes(
                         kpak_plain, key, kasumi::crypto::FilePurpose::Pack)
                         .value();

    return SeedCorpus{
        .kcom_bootstrap = encoded_bootstrap,
        .kcom_manifest = std::move(encoded_manifest),
        .marker = marker,
        .transaction = std::move(transaction),
        .kpak_plaintext = std::move(kpak_plain),
        .kact_plaintext = std::move(kact_plain),
        .epoch_plaintext = std::move(epoch_plain),
        .epoch_sealed = std::move(sealed.bytes),
        .aead_content = std::move(aead_content),
        .aead_pack = std::move(aead_pack),
        .epoch_ref = std::move(sealed.reference),
        .key = key,
    };
}

TEST(CodecFuzzTest, SeedCorpusDecodesCleanlyBeforeMutation) {
    const auto corpus = build_corpus();
    EXPECT_TRUE(kasumi::history::deserialize(corpus.kcom_bootstrap).has_value());
    EXPECT_TRUE(kasumi::history::deserialize(corpus.kcom_manifest).has_value());
    EXPECT_TRUE(
        kasumi::application::history_storage::decode_marker(corpus.marker)
            .has_value());
    std::vector<std::byte> journal(corpus.transaction.size());
    std::ranges::transform(corpus.transaction, journal.begin(), [](auto byte) {
        return static_cast<std::byte>(byte);
    });
    EXPECT_TRUE(kasumi::transaction::codec::decode(journal).has_value());
    EXPECT_TRUE(kasumi::crypto::pack::decode_verified_pack_plaintext(
                    corpus.kpak_plaintext)
                    .has_value());
    EXPECT_TRUE(kasumi::application::history_storage::activity::decode(
                    corpus.kact_plaintext)
                    .has_value());
    EXPECT_TRUE(kasumi::application::history_storage::epoch::decode(
                    corpus.epoch_plaintext)
                    .has_value());
    EXPECT_TRUE(kasumi::application::history_storage::epoch::open(
                    corpus.epoch_sealed, corpus.epoch_ref, corpus.key)
                    .has_value());
    EXPECT_TRUE(kasumi::crypto::decrypt_bytes(
                    corpus.aead_content, corpus.key,
                    kasumi::crypto::FilePurpose::Content)
                    .has_value());
    EXPECT_TRUE(kasumi::crypto::decrypt_bytes(
                    corpus.aead_pack, corpus.key,
                    kasumi::crypto::FilePurpose::Pack)
                    .has_value());
}

TEST(CodecFuzzTest, MutatedBinaryCodecsAndEnvelopesDoNotCrash) {
    const auto corpus = build_corpus();
    const std::array<const std::vector<std::uint8_t>*, 10> seeds{
        &corpus.kcom_bootstrap, &corpus.kcom_manifest, &corpus.marker,
        &corpus.transaction,    &corpus.kpak_plaintext, &corpus.kact_plaintext,
        &corpus.epoch_plaintext, &corpus.epoch_sealed, &corpus.aead_content,
        &corpus.aead_pack,
    };
    std::uint64_t state = 0x4b6173756d695232ULL;
    const auto count = iteration_count();
    for (std::size_t iteration = 0; iteration < count; ++iteration) {
        const auto kind = iteration % seeds.size();
        auto bytes = *seeds[kind];
        mutate(bytes, state);
        switch (kind) {
            case 0:
            case 1:
                static_cast<void>(kasumi::history::deserialize(bytes));
                break;
            case 2:
                static_cast<void>(
                    kasumi::application::history_storage::decode_marker(bytes));
                break;
            case 3: {
                std::vector<std::byte> journal(bytes.size());
                std::ranges::transform(bytes, journal.begin(), [](auto byte) {
                    return static_cast<std::byte>(byte);
                });
                static_cast<void>(kasumi::transaction::codec::decode(journal));
                break;
            }
            case 4:
                static_cast<void>(
                    kasumi::crypto::pack::decode_verified_pack_plaintext(
                        std::move(bytes)));
                break;
            case 5:
                static_cast<void>(
                    kasumi::application::history_storage::activity::decode(
                        bytes));
                break;
            case 6:
                static_cast<void>(
                    kasumi::application::history_storage::epoch::decode(bytes));
                break;
            case 7:
                static_cast<void>(
                    kasumi::application::history_storage::epoch::open(
                        bytes, corpus.epoch_ref, corpus.key));
                break;
            case 8:
                static_cast<void>(kasumi::crypto::decrypt_bytes(
                    bytes, corpus.key, kasumi::crypto::FilePurpose::Content));
                break;
            default:
                static_cast<void>(kasumi::crypto::decrypt_bytes(
                    bytes, corpus.key, kasumi::crypto::FilePurpose::Pack));
                break;
        }
    }
}

} // namespace
