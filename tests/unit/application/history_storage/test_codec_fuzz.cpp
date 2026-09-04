#include "application/history_storage/history_storage.hpp"
#include "core/history.hpp"
#include "core/operation.hpp"
#include "core/transaction/codec.hpp"
#include "core/transaction/types.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
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

void mutate(std::vector<std::uint8_t>& bytes, std::uint64_t& state) {
    const auto edit_count = 1U + random_index(state, 8U);
    for (std::size_t edit = 0; edit < edit_count; ++edit) {
        switch (random_index(state, 5U)) {
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
            default:
                if (bytes.size() > 1U) {
                    std::swap(bytes[random_index(state, bytes.size())],
                              bytes[random_index(state, bytes.size())]);
                }
                break;
        }
    }
}

std::array<std::vector<std::uint8_t>, 3> seed_corpus() {
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto encoded_commit = kasumi::history::serialize(commit).value();
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
    return {encoded_commit, marker, std::move(transaction)};
}

TEST(CodecFuzzTest, MutatedCommitHeadAndJournalInputsDoNotCrash) {
    const auto corpus = seed_corpus();
    std::uint64_t state = 0x4b6173756d695232ULL;
    for (std::size_t iteration = 0; iteration < iteration_count();
         ++iteration) {
        const auto kind = iteration % corpus.size();
        auto bytes = corpus[kind];
        mutate(bytes, state);
        if (kind == 0U) {
            static_cast<void>(kasumi::history::deserialize(bytes));
        } else if (kind == 1U) {
            static_cast<void>(
                kasumi::application::history_storage::decode_marker(bytes));
        } else {
            std::vector<std::byte> journal(bytes.size());
            std::ranges::transform(bytes, journal.begin(), [](auto byte) {
                return static_cast<std::byte>(byte);
            });
            static_cast<void>(kasumi::transaction::codec::decode(journal));
        }
    }
}

} // namespace
