#include "application/history_storage/remote_layout.hpp"

#include <algorithm>
#include <charconv>

namespace kasumi::application::history_storage {

namespace {

constexpr std::size_t HASH_HEX_SIZE = 64;
constexpr std::size_t SEQUENCE_WIDTH = 20;

bool valid_hex_hash(std::string_view value) noexcept {
    return value.size() == HASH_HEX_SIZE &&
           std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

} // namespace

RemoteLayout default_remote_layout() {
    return RemoteLayout{
        .history_prefix = "history/",
        .commits_prefix = "history/commits/",
        .heads_prefix = "history/heads/",
        .epochs_prefix = "history/epochs/v1/",
        .gc_prefix = "history/gc/v1/",
        .barrier_identifier = "history/gc/v1/barrier",
        .writers_prefix = "history/gc/v1/writers/",
        .probes_prefix = "history/gc/v1/probes/",
        .quarantine_prefix = "history/gc/v1/quarantine/",
        .quarantine_content_prefix = "history/gc/v1/quarantine/content/",
        .quarantine_commits_prefix = "history/gc/v1/quarantine/commits/",
    };
}

RemoteLayout derive_remote_layout(
    std::span<const std::uint8_t, crypto::KEY_SIZE> master_key) {
    const auto history_hash =
        crypto::namespace_identifier(master_key, "history", 8);
    const auto commits_hash =
        crypto::namespace_identifier(master_key, "commits", 8);
    const auto heads_hash =
        crypto::namespace_identifier(master_key, "heads", 8);
    const auto epochs_hash =
        crypto::namespace_identifier(master_key, "epochs", 8);
    const auto v1_hash = crypto::namespace_identifier(master_key, "v1", 4);
    const auto gc_hash = crypto::namespace_identifier(master_key, "gc", 8);
    const auto barrier_hash =
        crypto::namespace_identifier(master_key, "barrier", 8);
    const auto writers_hash =
        crypto::namespace_identifier(master_key, "writers", 8);
    const auto probes_hash =
        crypto::namespace_identifier(master_key, "probes", 8);
    const auto quarantine_hash =
        crypto::namespace_identifier(master_key, "quarantine", 8);
    const auto content_hash =
        crypto::namespace_identifier(master_key, "content", 8);

    RemoteLayout layout;
    layout.history_prefix = history_hash + "/";
    layout.commits_prefix = layout.history_prefix + commits_hash + "/";
    layout.heads_prefix = layout.history_prefix + heads_hash + "/";
    layout.epochs_prefix =
        layout.history_prefix + epochs_hash + "/" + v1_hash + "/";
    layout.gc_prefix = layout.history_prefix + gc_hash + "/" + v1_hash + "/";
    layout.barrier_identifier = layout.gc_prefix + barrier_hash;
    layout.writers_prefix = layout.gc_prefix + writers_hash + "/";
    layout.probes_prefix = layout.gc_prefix + probes_hash + "/";
    layout.quarantine_prefix = layout.gc_prefix + quarantine_hash + "/";
    layout.quarantine_content_prefix =
        layout.quarantine_prefix + content_hash + "/";
    layout.quarantine_commits_prefix =
        layout.quarantine_prefix + commits_hash + "/";
    return layout;
}

std::string marker_object(const RemoteLayout& layout,
                          const HeadReference& reference) {
    return layout.heads_prefix + reference.commit_id + "-" +
           reference.ciphertext_id;
}

std::optional<HeadReference> parse_marker_object(const RemoteLayout& layout,
                                                 std::string_view identifier) {
    if (!identifier.starts_with(layout.heads_prefix)) {
        return std::nullopt;
    }
    const auto body = identifier.substr(layout.heads_prefix.size());
    if (body.size() != 129 || body[64] != '-') {
        return std::nullopt;
    }

    HeadReference result{
        .commit_id = std::string{body.substr(0, 64)},
        .ciphertext_id = std::string{body.substr(65)},
    };
    return valid(result) ? std::optional{std::move(result)} : std::nullopt;
}

std::string commit_object(const RemoteLayout& layout,
                          const HeadReference& reference) {
    return layout.commits_prefix + reference.commit_id + "/" +
           reference.ciphertext_id;
}

std::optional<HeadReference> parse_commit_object(const RemoteLayout& layout,
                                                 std::string_view identifier) {
    if (!identifier.starts_with(layout.commits_prefix)) {
        return std::nullopt;
    }
    const auto body = identifier.substr(layout.commits_prefix.size());
    const auto separator = body.find('/');
    if (separator != 64 ||
        body.find('/', separator + 1) != std::string_view::npos ||
        body.size() != 129) {
        return std::nullopt;
    }

    HeadReference result{
        .commit_id = std::string{body.substr(0, separator)},
        .ciphertext_id = std::string{body.substr(separator + 1)},
    };
    return valid(result) ? std::optional{std::move(result)} : std::nullopt;
}

std::string epoch_object(const RemoteLayout& layout,
                         std::uint64_t sequence,
                         std::string_view epoch_id) {
    auto sequence_text = std::to_string(sequence);
    if (sequence_text.size() < SEQUENCE_WIDTH) {
        sequence_text.insert(
            sequence_text.begin(), SEQUENCE_WIDTH - sequence_text.size(), '0');
    }
    return layout.epochs_prefix + sequence_text + '-' + std::string{epoch_id};
}

std::string epoch_object(const RemoteLayout& layout,
                         const epoch::Reference& reference) {
    return epoch_object(layout, reference.sequence, reference.epoch_id);
}

std::optional<epoch::Reference>
parse_epoch_object(const RemoteLayout& layout, std::string_view identifier) {
    if (!identifier.starts_with(layout.epochs_prefix)) {
        return std::nullopt;
    }
    const auto body = identifier.substr(layout.epochs_prefix.size());
    const auto expected_size = SEQUENCE_WIDTH + 1 + HASH_HEX_SIZE;
    if (body.size() != expected_size || body[SEQUENCE_WIDTH] != '-') {
        return std::nullopt;
    }

    const auto sequence_text = body.substr(0, SEQUENCE_WIDTH);
    if (!std::ranges::all_of(sequence_text, [](char c) {
            return c >= '0' && c <= '9';
        })) {
        return std::nullopt;
    }

    std::uint64_t sequence = 0;
    const auto parsed =
        std::from_chars(sequence_text.data(),
                        sequence_text.data() + sequence_text.size(),
                        sequence);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != sequence_text.data() + sequence_text.size()) {
        return std::nullopt;
    }

    const auto epoch_id = body.substr(SEQUENCE_WIDTH + 1, HASH_HEX_SIZE);
    epoch::Reference result{.sequence = sequence,
                            .epoch_id = std::string{epoch_id}};
    return valid_hex_hash(result.epoch_id) ? std::optional{std::move(result)}
                                           : std::nullopt;
}

bool is_control_object(const RemoteLayout& layout,
                       std::string_view identifier) noexcept {
    return identifier == layout.barrier_identifier ||
           identifier.starts_with(layout.writers_prefix) ||
           identifier.starts_with(layout.probes_prefix) ||
           identifier.starts_with(layout.quarantine_prefix);
}

bool is_history_object(const RemoteLayout& layout,
                       std::string_view identifier) noexcept {
    return identifier.starts_with(layout.history_prefix);
}

std::optional<std::string>
quarantine_identifier(const RemoteLayout& layout,
                      std::string_view original_identifier) {
    if (original_identifier.starts_with(layout.commits_prefix)) {
        return layout.quarantine_commits_prefix +
               std::string{
                   original_identifier.substr(layout.commits_prefix.size())};
    }
    if (valid_hex_hash(original_identifier)) {
        return layout.quarantine_content_prefix +
               std::string{original_identifier};
    }
    return std::nullopt;
}

std::optional<std::string>
restore_destination(const RemoteLayout& layout,
                    std::string_view quarantine_identifier) {
    if (quarantine_identifier.starts_with(layout.quarantine_content_prefix)) {
        const auto content = quarantine_identifier.substr(
            layout.quarantine_content_prefix.size());
        if (valid_hex_hash(content)) {
            return std::string{content};
        }
        return std::nullopt;
    }
    if (quarantine_identifier.starts_with(layout.quarantine_commits_prefix)) {
        const auto body = quarantine_identifier.substr(
            layout.quarantine_commits_prefix.size());
        const auto original = layout.commits_prefix + std::string{body};
        if (parse_commit_object(layout, original)) {
            return original;
        }
    }
    return std::nullopt;
}

} // namespace kasumi::application::history_storage
