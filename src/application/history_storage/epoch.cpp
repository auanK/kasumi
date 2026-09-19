#include "application/history_storage/epoch.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/wire.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <exception>
#include <limits>
#include <monocypher.h>
#include <unordered_map>
#include <utility>

namespace kasumi::application::history_storage::epoch {

namespace {

inline constexpr std::array<std::byte, 4> epoch_magic{
    std::byte{'K'}, std::byte{'E'}, std::byte{'P'}, std::byte{'O'}};
inline constexpr std::array<std::uint8_t, 5> envelope_header{
    'K', 'E', 'P', 'A', 1};
inline constexpr std::uint8_t format_version = 1;
inline constexpr std::size_t sequence_width = 20;
inline constexpr std::size_t mac_size = 16;
inline constexpr std::size_t nonce_size = 24;
inline constexpr std::string_view object_prefix = "history/epochs/v1/";
inline constexpr std::string_view object_directory = "history/epochs/v1";
inline constexpr std::string_view object_suffix = ".epoch";

Error error(ErrorCode code, std::string detail) {
    return Error{.code = code, .detail = std::move(detail)};
}

bool valid_id(std::string_view value) noexcept {
    return value.size() == HASH_HEX_SIZE &&
           std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

std::expected<void, Error> validate(const Epoch& value) {
    if (!valid_id(value.vault_id)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid vault ID"));
    }
    if (value.issued_at < 0) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid epoch timestamp"));
    }
    if (value.policy.min_history_depth == 0 ||
        value.policy.min_history_depth > history::maximum_graph_depth ||
        value.policy.min_history_age_hours == 0) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid retention policy"));
    }
    if (value.anchors.empty()) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "epoch has no anchors"));
    }
    if (value.anchors.size() > maximum_anchor_count) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "epoch has too many anchors"));
    }
    std::string_view previous;
    for (const auto& anchor : value.anchors) {
        if (!valid_id(anchor.commit_id)) {
            return std::unexpected(
                error(ErrorCode::InvalidInput, "invalid anchor commit ID"));
        }
        if (!previous.empty() && anchor.commit_id <= previous) {
            return std::unexpected(error(ErrorCode::InvalidInput,
                                         "anchors are not strictly ordered"));
        }
        previous = anchor.commit_id;
    }
    if ((value.sequence == 0 && !value.previous_epoch_id.empty()) ||
        (value.sequence != 0 && !valid_id(value.previous_epoch_id))) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid previous epoch reference"));
    }
    return {};
}

std::expected<Hash, Error> id_bytes(std::string_view identifier) {
    if (!valid_id(identifier)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid epoch ID"));
    }
    auto parsed = hash_from_hex(identifier);
    if (!parsed) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid epoch ID"));
    }
    return *parsed;
}

std::array<std::uint8_t, nonce_size> nonce_from_id(const Hash& identifier) {
    std::array<std::uint8_t, nonce_size> nonce{};
    std::transform(identifier.begin(),
                   identifier.begin() +
                       static_cast<std::ptrdiff_t>(nonce.size()),
                   nonce.begin(),
                   [](std::byte value) {
                       return std::to_integer<std::uint8_t>(value);
                   });
    return nonce;
}

void write_id(wire::Writer& writer, std::string_view identifier) {
    wire::write_array(writer, hash_from_hex(identifier).value());
}

std::expected<std::string, Error> read_id(wire::Reader& reader) {
    auto value = wire::read_array<HASH_SIZE>(reader);
    if (!value) {
        return std::unexpected(
            error(ErrorCode::InvalidEncoding, "truncated identifier"));
    }
    return hash_hex(*value);
}

std::expected<void, Error> validate_verified(const VerifiedEpoch& value) {
    if (value.reference.sequence != value.value.sequence ||
        !valid_id(value.reference.epoch_id)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "inconsistent verified epoch"));
    }
    auto canonical = encode(value.value);
    if (!canonical) {
        return std::unexpected(canonical.error());
    }
    return {};
}

struct EpochInventory {
    std::vector<Reference> references;
};

std::expected<EpochInventory, Error> discover_epoch_inventory(
    transport::Transport& storage,
    const RemoteLayout& layout,
    std::optional<std::span<const std::string>> known_identifiers,
    bool require_contiguous_chain = true) {
    std::vector<std::string> identifiers;
    if (known_identifiers) {
        for (const auto& identifier : *known_identifiers) {
            if (identifier.starts_with(layout.epochs_prefix) ||
                identifier.starts_with("history/epochs/v1/")) {
                identifiers.push_back(identifier);
            }
        }
    } else {
        const auto directory = layout.epochs_prefix.ends_with('/')
                                   ? layout.epochs_prefix.substr(
                                         0, layout.epochs_prefix.size() - 1)
                                   : layout.epochs_prefix;
        auto listed = transport::list(storage, directory);
        if (!listed) {
            if (listed.error().code == transport::ErrorCode::StorageNotFound) {
                return EpochInventory{};
            }
            return std::unexpected(error(ErrorCode::TransportFailure,
                                         transport::describe(listed.error())));
        }
        identifiers.reserve(listed->size());
        for (const auto& name : *listed) {
            identifiers.push_back(name.starts_with(layout.epochs_prefix)
                                      ? name
                                      : layout.epochs_prefix + name);
        }
    }

    EpochInventory inventory;
    inventory.references.reserve(identifiers.size());
    std::unordered_map<std::uint64_t, std::string> ids_by_sequence;
    std::unordered_map<std::string, std::uint64_t> sequences_by_id;
    ids_by_sequence.reserve(identifiers.size());
    sequences_by_id.reserve(identifiers.size());
    for (const auto& identifier : identifiers) {
        auto reference = parse_object_identifier(layout, identifier);
        if (!reference) {
            return std::unexpected(reference.error());
        }

        const auto sequence = ids_by_sequence.find(reference->sequence);
        if (sequence != ids_by_sequence.end()) {
            if (sequence->second != reference->epoch_id) {
                return std::unexpected(
                    error(ErrorCode::Conflict,
                          "epoch sequence has multiple identifiers"));
            }
            continue;
        }
        const auto id = sequences_by_id.find(reference->epoch_id);
        if (id != sequences_by_id.end() && id->second != reference->sequence) {
            return std::unexpected(
                error(ErrorCode::Conflict,
                      "epoch identifier appears in multiple sequences"));
        }
        ids_by_sequence.emplace(reference->sequence, reference->epoch_id);
        sequences_by_id.emplace(reference->epoch_id, reference->sequence);
        inventory.references.push_back(std::move(*reference));
    }

    std::ranges::sort(inventory.references,
                      [](const auto& left, const auto& right) {
                          return left.sequence < right.sequence;
                      });
    if (inventory.references.empty() || !require_contiguous_chain) {
        return inventory;
    }
    if (inventory.references.front().sequence != 0) {
        return std::unexpected(
            error(ErrorCode::Conflict, "epoch chain missing genesis"));
    }
    for (std::size_t index = 1; index < inventory.references.size(); ++index) {
        const auto previous = inventory.references[index - 1].sequence;
        if (previous == std::numeric_limits<std::uint64_t>::max() ||
            inventory.references[index].sequence != previous + 1) {
            return std::unexpected(
                error(ErrorCode::Conflict, "epoch chain has gap"));
        }
    }
    return inventory;
}

std::expected<VerifiedEpoch, Error>
load_exact_reference(transport::Transport& storage,
                     const RemoteLayout& layout,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
                     const detail::TemporaryWorkspace& temporary,
                     const Reference& reference,
                     std::size_t request_index) {
    auto identifier = object_identifier(layout, reference);
    if (!identifier) {
        return std::unexpected(identifier.error());
    }
    const auto copy =
        temporary->root / ("epoch-" + std::to_string(request_index));
    const auto get_trace = platform::perf_trace::begin();
    auto downloaded = detail::download(storage, *identifier, copy);

    platform::perf_trace::finish("rc/get_epoch", get_trace);
    if (!downloaded) {
        return std::unexpected(
            error(ErrorCode::TransportFailure, downloaded.error().detail));
    }
    auto bytes = detail::read_file(
        copy, envelope_header.size() + mac_size + maximum_encoded_size);
    if (!bytes) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, bytes.error().detail));
    }
    return open(*bytes, reference, master_key);
}

LatestResult
load_latest_impl(transport::Transport& storage,
                 std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
                 const std::filesystem::path& workspace_root,
                 std::optional<std::span<const std::string>> known_identifiers,
                 std::optional<Reference> trusted_ancestor) {
    const auto layout = derive_remote_layout(master_key);
    auto inventory =
        discover_epoch_inventory(storage, layout, known_identifiers);
    if (!inventory) {
        return std::unexpected(inventory.error());
    }
    if (inventory->references.empty()) {
        return std::optional<VerifiedEpoch>{};
    }
    const auto& latest_reference = inventory->references.back();
    if (trusted_ancestor &&
        (trusted_ancestor->sequence > latest_reference.sequence ||
         (trusted_ancestor->sequence == latest_reference.sequence &&
          trusted_ancestor->epoch_id != latest_reference.epoch_id))) {
        return std::unexpected(
            error(ErrorCode::Conflict,
                  "remote epoch regressed from exact local checkpoint"));
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, temporary.error().detail));
    }

    std::size_t request_index = 0;
    auto latest = load_exact_reference(storage,
                                       layout,
                                       master_key,
                                       *temporary,
                                       latest_reference,
                                       request_index++);
    if (!latest) {
        return std::unexpected(latest.error());
    }
    const auto& contract = latest->value;
    auto current = *latest;
    std::size_t index = inventory->references.size() - 1;
    while (current.reference.sequence != 0 &&
           (!trusted_ancestor ||
            current.reference.sequence > trusted_ancestor->sequence)) {
        if (index == 0 || current.value.previous_epoch_id !=
                              inventory->references[index - 1].epoch_id) {
            return std::unexpected(error(
                ErrorCode::Conflict, "epoch ancestry has invalid predecessor"));
        }
        --index;
        auto previous = load_exact_reference(storage,
                                             layout,
                                             master_key,
                                             *temporary,
                                             inventory->references[index],
                                             request_index++);
        if (!previous) {
            return std::unexpected(previous.error());
        }
        if (previous->value.vault_id != contract.vault_id ||
            previous->value.policy != contract.policy) {
            return std::unexpected(
                error(ErrorCode::Conflict,
                      "epoch ancestry diverges from authenticated contract"));
        }
        current = std::move(*previous);
    }
    if (trusted_ancestor && current.reference != *trusted_ancestor) {
        return std::unexpected(error(
            ErrorCode::Conflict, "ancestry does not reach exact checkpoint"));
    }
    return std::optional<VerifiedEpoch>{std::move(*latest)};
}

ChainResult
load_chain_impl(transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
                const std::filesystem::path& workspace_root,
                std::optional<std::span<const std::string>> identifiers) {
    const auto layout = derive_remote_layout(master_key);
    auto inventory = discover_epoch_inventory(storage, layout, identifiers);
    if (!inventory) {
        return std::unexpected(inventory.error());
    }
    if (inventory->references.empty()) {
        return std::vector<VerifiedEpoch>{};
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, temporary.error().detail));
    }

    std::vector<VerifiedEpoch> chain;
    chain.reserve(inventory->references.size());
    for (std::size_t index = 0; index < inventory->references.size(); ++index) {
        auto loaded = load_exact_reference(storage,
                                           layout,
                                           master_key,
                                           *temporary,
                                           inventory->references[index],
                                           index);
        if (!loaded) {
            return std::unexpected(loaded.error());
        }
        chain.push_back(std::move(*loaded));
    }
    if (auto validated = select_latest(chain); !validated) {
        return std::unexpected(validated.error());
    }
    return chain;
}

} // namespace

BytesResult encode(const Epoch& value) {
    if (auto valid = validate(value); !valid) {
        return std::unexpected(valid.error());
    }
    try {
        wire::Writer writer;
        wire::write_array(writer, epoch_magic);
        wire::write(writer, format_version);
        write_id(writer, value.vault_id);
        wire::write(writer, value.sequence);
        wire::write(writer, value.issued_at);
        wire::write(writer, value.policy.min_history_depth);
        wire::write(writer, value.policy.min_history_age_hours);
        if (value.sequence != 0) {
            write_id(writer, value.previous_epoch_id);
        }
        wire::write(writer, static_cast<std::uint32_t>(value.anchors.size()));
        for (const auto& anchor : value.anchors) {
            write_id(writer, anchor.commit_id);
            wire::write(writer, anchor.height);
        }
        if (writer.buffer.size() > maximum_encoded_size) {
            return std::unexpected(
                error(ErrorCode::LimitExceeded, "epoch exceeds maximum size"));
        }
        std::vector<std::uint8_t> result(writer.buffer.size());
        std::transform(writer.buffer.begin(),
                       writer.buffer.end(),
                       result.begin(),
                       [](std::byte byte) {
                           return std::to_integer<std::uint8_t>(byte);
                       });
        return result;
    } catch (const std::exception& exception) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded,
                  std::string{"failed to encode epoch: "} + exception.what()));
    }
}

std::expected<Epoch, Error> decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > maximum_encoded_size) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "epoch exceeds maximum size"));
    }
    try {
        wire::Reader reader{std::as_bytes(bytes)};
        auto magic = wire::read_array<epoch_magic.size()>(reader);
        if (!magic || *magic != epoch_magic) {
            return std::unexpected(
                error(ErrorCode::InvalidEncoding, "invalid epoch magic"));
        }
        auto version = wire::read<std::uint8_t>(reader);
        if (!version) {
            return std::unexpected(
                error(ErrorCode::InvalidEncoding, "missing epoch version"));
        }
        if (*version != format_version) {
            return std::unexpected(error(ErrorCode::UnsupportedVersion,
                                         "unsupported epoch version"));
        }
        auto vault_id = read_id(reader);
        auto sequence = wire::read<std::uint64_t>(reader);
        auto issued_at = wire::read<std::int64_t>(reader);
        auto depth = wire::read<std::uint32_t>(reader);
        auto age = wire::read<std::uint32_t>(reader);
        if (!vault_id || !sequence || !issued_at || !depth || !age) {
            return std::unexpected(
                error(ErrorCode::InvalidEncoding, "truncated epoch"));
        }

        std::string previous_epoch_id;
        if (*sequence != 0) {
            auto previous = read_id(reader);
            if (!previous) {
                return std::unexpected(previous.error());
            }
            previous_epoch_id = std::move(*previous);
        }

        auto anchor_count = wire::read<std::uint32_t>(reader);
        if (!anchor_count) {
            return std::unexpected(
                error(ErrorCode::InvalidEncoding, "missing anchor count"));
        }
        if (*anchor_count > maximum_anchor_count) {
            return std::unexpected(
                error(ErrorCode::LimitExceeded, "epoch has too many anchors"));
        }

        Epoch value{
            .vault_id = std::move(*vault_id),
            .sequence = *sequence,
            .issued_at = *issued_at,
            .policy = {.min_history_depth = *depth,
                       .min_history_age_hours = *age},
            .anchors = {},
            .previous_epoch_id = std::move(previous_epoch_id),
        };
        value.anchors.reserve(*anchor_count);
        for (std::uint32_t index = 0; index < *anchor_count; ++index) {
            auto commit_id = read_id(reader);
            auto height = wire::read<std::uint64_t>(reader);
            if (!commit_id || !height) {
                return std::unexpected(
                    error(ErrorCode::InvalidEncoding, "truncated anchor"));
            }
            value.anchors.push_back(
                Anchor{.commit_id = std::move(*commit_id), .height = *height});
        }
        if (!reader.data.empty()) {
            return std::unexpected(error(ErrorCode::InvalidEncoding,
                                         "residual bytes after epoch"));
        }
        if (auto valid = validate(value); !valid) {
            return std::unexpected(valid.error());
        }
        return value;
    } catch (const std::exception& exception) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded,
                  std::string{"failed to decode epoch: "} + exception.what()));
    }
}

std::expected<SealedEpoch, Error>
seal(const Epoch& value,
     std::span<const std::uint8_t, crypto::KEY_SIZE> master_key) {
    auto canonical = encode(value);
    if (!canonical) {
        return std::unexpected(canonical.error());
    }
    try {
        const auto identifier =
            crypto::epoch_identifier(master_key, *canonical);
        const auto parsed_id = id_bytes(identifier).value();
        const auto nonce = nonce_from_id(parsed_id);
        std::vector<std::uint8_t> bytes(envelope_header.size() + mac_size +
                                        canonical->size());
        std::ranges::copy(envelope_header, bytes.begin());
        auto key = crypto::derive_key(master_key, crypto::KeyPurpose::Epoch);
        crypto_aead_lock(bytes.data() + envelope_header.size() + mac_size,
                         bytes.data() + envelope_header.size(),
                         key.data(),
                         nonce.data(),
                         envelope_header.data(),
                         envelope_header.size(),
                         canonical->data(),
                         canonical->size());
        crypto_wipe(key.data(), key.size());
        return SealedEpoch{
            .reference = {.sequence = value.sequence, .epoch_id = identifier},
            .bytes = std::move(bytes),
        };
    } catch (const std::exception& exception) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded,
                  std::string{"failed to seal epoch: "} + exception.what()));
    }
}

std::expected<VerifiedEpoch, Error>
open(std::span<const std::uint8_t> bytes,
     const Reference& reference,
     std::span<const std::uint8_t, crypto::KEY_SIZE> master_key) {
    auto parsed_id = id_bytes(reference.epoch_id);
    if (!parsed_id) {
        return std::unexpected(parsed_id.error());
    }
    if (bytes.size() < envelope_header.size() + mac_size ||
        bytes.size() >
            envelope_header.size() + mac_size + maximum_encoded_size) {
        return std::unexpected(error(ErrorCode::InvalidEncoding,
                                     "epoch envelope has invalid size"));
    }
    if (!std::ranges::equal(envelope_header,
                            bytes.first(envelope_header.size()))) {
        return std::unexpected(
            error(ErrorCode::UnsupportedVersion, "unsupported epoch envelope"));
    }

    try {
        const auto nonce = nonce_from_id(*parsed_id);
        const auto ciphertext =
            bytes.subspan(envelope_header.size() + mac_size);
        std::vector<std::uint8_t> plaintext(ciphertext.size());
        auto key = crypto::derive_key(master_key, crypto::KeyPurpose::Epoch);
        const auto unlocked =
            crypto_aead_unlock(plaintext.data(),
                               bytes.data() + envelope_header.size(),
                               key.data(),
                               nonce.data(),
                               envelope_header.data(),
                               envelope_header.size(),
                               ciphertext.data(),
                               ciphertext.size());
        crypto_wipe(key.data(), key.size());
        if (unlocked != 0) {
            crypto_wipe(plaintext.data(), plaintext.size());
            return std::unexpected(error(ErrorCode::AuthenticationFailure,
                                         "epoch authentication failed"));
        }

        const auto identifier = crypto::epoch_identifier(master_key, plaintext);
        if (identifier != reference.epoch_id) {
            crypto_wipe(plaintext.data(), plaintext.size());
            return std::unexpected(error(ErrorCode::AuthenticationFailure,
                                         "epoch does not match identifier"));
        }
        auto value = decode(plaintext);
        crypto_wipe(plaintext.data(), plaintext.size());
        if (!value) {
            return std::unexpected(value.error());
        }
        if (value->sequence != reference.sequence) {
            return std::unexpected(error(ErrorCode::AuthenticationFailure,
                                         "epoch does not match sequence"));
        }
        return VerifiedEpoch{.reference = reference,
                             .value = std::move(*value)};
    } catch (const std::exception& exception) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded,
                  std::string{"failed to open epoch: "} + exception.what()));
    }
}

std::expected<std::string, Error>
object_identifier(const RemoteLayout& layout, const Reference& reference) {
    if (!valid_id(reference.epoch_id)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid epoch reference"));
    }
    return epoch_object(layout, reference.sequence, reference.epoch_id);
}

std::expected<std::string, Error>
object_identifier(const Reference& reference) {
    return object_identifier(default_remote_layout(), reference);
}

std::expected<Reference, Error>
parse_object_identifier(const RemoteLayout& layout,
                        std::string_view identifier) {
    auto parsed = parse_epoch_object(layout, identifier);
    if (!parsed) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid epoch object name"));
    }
    return Reference{.sequence = parsed->sequence,
                     .epoch_id = std::move(parsed->epoch_id)};
}

std::expected<Reference, Error>
parse_object_identifier(std::string_view identifier) {
    return parse_object_identifier(default_remote_layout(), identifier);
}

std::expected<VerifiedEpoch, Error>
select_latest(std::span<const VerifiedEpoch> epochs) {
    if (epochs.empty()) {
        return std::unexpected(
            error(ErrorCode::NotFound, "no epochs available"));
    }
    const auto& contract = epochs.front().value;
    std::vector<const VerifiedEpoch*> unique;
    unique.reserve(epochs.size());
    std::unordered_map<std::uint64_t, const VerifiedEpoch*> sequences;
    sequences.reserve(epochs.size());
    for (const auto& candidate : epochs) {
        if (auto valid = validate_verified(candidate); !valid) {
            return std::unexpected(valid.error());
        }
        if (candidate.value.vault_id != contract.vault_id ||
            candidate.value.policy != contract.policy) {
            return std::unexpected(error(
                ErrorCode::Conflict, "epochs belong to different contracts"));
        }
        const auto [known, inserted] =
            sequences.emplace(candidate.reference.sequence, &candidate);
        if (!inserted) {
            if (candidate != *known->second) {
                return std::unexpected(
                    error(ErrorCode::Conflict, "epoch sequence has conflict"));
            }
            continue;
        }
        unique.push_back(&candidate);
    }
    std::ranges::sort(unique, [](const auto* left, const auto* right) {
        return left->reference.sequence < right->reference.sequence;
    });
    if (unique.front()->reference.sequence != 0) {
        return std::unexpected(
            error(ErrorCode::Conflict, "epoch chain missing genesis"));
    }
    for (std::size_t index = 1; index < unique.size(); ++index) {
        const auto previous = unique[index - 1];
        const auto current = unique[index];
        if (previous->reference.sequence ==
            std::numeric_limits<std::uint64_t>::max()) {
            return std::unexpected(error(
                ErrorCode::Conflict, "epoch chain exceeds maximum sequence"));
        }
        if (current->reference.sequence != previous->reference.sequence + 1 ||
            current->value.previous_epoch_id != previous->reference.epoch_id) {
            return std::unexpected(
                error(ErrorCode::Conflict, "epoch chain has discontinuity"));
        }
    }
    return *unique.back();
}

std::expected<void, Error>
publish(transport::Transport& storage,
        const RemoteLayout& layout,
        const SealedEpoch& sealed,
        const std::filesystem::path& workspace_root) {
    auto identifier = object_identifier(layout, sealed.reference);
    if (!identifier || sealed.bytes.empty()) {
        return std::unexpected(
            identifier ? error(ErrorCode::InvalidInput, "empty sealed epoch")
                       : identifier.error());
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, temporary.error().detail));
    }
    const auto source = (*temporary)->root / "epoch.source";
    if (auto written = detail::write_file(source, sealed.bytes); !written) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, written.error().detail));
    }
    auto uploaded = transport::put(storage, source, *identifier);
    if (!uploaded) {
        return std::unexpected(error(ErrorCode::TransportFailure,
                                     transport::describe(uploaded.error())));
    }
    return {};
}

std::expected<void, Error>
publish(transport::Transport& storage,
        std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
        const SealedEpoch& sealed,
        const std::filesystem::path& workspace_root) {
    return publish(
        storage, derive_remote_layout(master_key), sealed, workspace_root);
}

std::expected<void, Error>
publish(transport::Transport& storage,
        const SealedEpoch& sealed,
        const std::filesystem::path& workspace_root) {
    return publish(storage, default_remote_layout(), sealed, workspace_root);
}

std::expected<void, Error>
verify(transport::Transport& storage,
       const Epoch& expected,
       const Reference& reference,
       std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
       const std::filesystem::path& workspace_root) {
    const auto layout = derive_remote_layout(master_key);
    auto identifier = object_identifier(layout, reference);
    if (!identifier) {
        return std::unexpected(identifier.error());
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, temporary.error().detail));
    }
    const auto copy = (*temporary)->root / "epoch.copy";
    if (auto downloaded = detail::download(storage, *identifier, copy);
        !downloaded) {
        return std::unexpected(
            error(ErrorCode::TransportFailure, downloaded.error().detail));
    }
    auto bytes = detail::read_file(
        copy, envelope_header.size() + mac_size + maximum_encoded_size);
    if (!bytes) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, bytes.error().detail));
    }
    auto verified = open(*bytes, reference, master_key);
    if (!verified || verified->value != expected) {
        return std::unexpected(error(ErrorCode::VerificationFailure,
                                     verified
                                         ? "remote epoch diverges from expected"
                                         : verified.error().detail));
    }
    return {};
}

LatestResult
load_latest(transport::Transport& storage,
            std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
            const std::filesystem::path& workspace_root) {
    try {
        return load_latest_impl(
            storage, master_key, workspace_root, std::nullopt, std::nullopt);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

LatestResult
load_latest(transport::Transport& storage,
            std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
            const std::filesystem::path& workspace_root,
            std::span<const std::string> identifiers) {
    try {
        return load_latest_impl(
            storage, master_key, workspace_root, identifiers, std::nullopt);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

LatestResult
load_latest(transport::Transport& storage,
            std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
            const std::filesystem::path& workspace_root,
            std::optional<Reference> trusted_ancestor) {
    try {
        return load_latest_impl(storage,
                                master_key,
                                workspace_root,
                                std::nullopt,
                                std::move(trusted_ancestor));
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

LatestResult
load_latest(transport::Transport& storage,
            std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
            const std::filesystem::path& workspace_root,
            std::span<const std::string> identifiers,
            std::optional<Reference> trusted_ancestor) {
    try {
        return load_latest_impl(storage,
                                master_key,
                                workspace_root,
                                identifiers,
                                std::move(trusted_ancestor));
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

ChainResult
load_chain(transport::Transport& storage,
           std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
           const std::filesystem::path& workspace_root) {
    try {
        return load_chain_impl(
            storage, master_key, workspace_root, std::nullopt);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

ChainResult
load_chain(transport::Transport& storage,
           std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
           const std::filesystem::path& workspace_root,
           std::span<const std::string> identifiers) {
    try {
        return load_chain_impl(
            storage, master_key, workspace_root, identifiers);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

LatestResult
load_by_id(transport::Transport& storage,
           std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
           const std::filesystem::path& workspace_root,
           std::string_view epoch_id) {
    try {
        if (!valid_id(epoch_id)) {
            return std::unexpected(
                error(ErrorCode::InvalidInput, "invalid epoch ID"));
        }

        const auto layout = derive_remote_layout(master_key);
        const auto directory = layout.epochs_prefix.ends_with('/')
                                   ? layout.epochs_prefix.substr(
                                         0, layout.epochs_prefix.size() - 1)
                                   : layout.epochs_prefix;
        auto listed = transport::list(storage, directory);
        if (!listed) {
            if (listed.error().code == transport::ErrorCode::StorageNotFound) {
                return std::optional<VerifiedEpoch>{};
            }
            return std::unexpected(error(ErrorCode::TransportFailure,
                                         transport::describe(listed.error())));
        }
        std::vector<std::string> identifiers;
        identifiers.reserve(listed->size());
        for (const auto& name : *listed) {
            identifiers.push_back(name.starts_with(layout.epochs_prefix)
                                      ? name
                                      : layout.epochs_prefix + name);
        }
        auto inventory = discover_epoch_inventory(
            storage,
            layout,
            std::optional<std::span<const std::string>>{
                std::span<const std::string>{identifiers}},
            false);
        if (!inventory) {
            return std::unexpected(inventory.error());
        }
        const auto matching = std::ranges::find_if(
            inventory->references, [epoch_id](const auto& reference) {
                return reference.epoch_id == epoch_id;
            });
        if (matching == inventory->references.end()) {
            return std::optional<VerifiedEpoch>{};
        }
        auto temporary = detail::make_workspace(workspace_root);
        if (!temporary) {
            return std::unexpected(
                error(ErrorCode::WorkspaceFailure, temporary.error().detail));
        }
        auto loaded = load_exact_reference(
            storage, layout, master_key, *temporary, *matching, 0);
        if (!loaded) {
            return std::unexpected(loaded.error());
        }
        return std::optional<VerifiedEpoch>{std::move(*loaded)};
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

PruneResult plan_pruning(std::span<const kasumi::history::LoadedCommit> commits,
                         const RetentionPolicy& policy) {
    if (commits.size() > kasumi::history::maximum_loaded_commit_count) {
        return std::unexpected(NoPrune{"defensive limit exceeded"});
    }

    std::unordered_map<std::string, const kasumi::history::LoadedCommit*> by_id;
    std::unordered_set<std::string> has_parents;
    for (const auto& c : commits) {
        by_id[c.id] = &c;
        for (const auto& p : c.commit.parents) {
            has_parents.insert(p);
        }
    }

    std::vector<std::string> heads;
    for (const auto& c : commits) {
        if (!has_parents.contains(c.id)) {
            heads.push_back(c.id);
        }
    }

    for (const auto& c : commits) {
        for (const auto& parent : c.commit.parents) {
            const auto parent_it = by_id.find(parent);
            if (parent_it != by_id.end() &&
                parent_it->second->commit.created_at > c.commit.created_at) {
                return std::unexpected(
                    NoPrune{"timestamp regression detected"});
            }
        }
    }

    std::int64_t newest_authenticated_head = 0;
    for (const auto& head : heads) {
        const auto head_it = by_id.find(head);
        if (head_it != by_id.end()) {
            newest_authenticated_head = std::max(
                newest_authenticated_head, head_it->second->commit.created_at);
        }
    }
    if (newest_authenticated_head <= 0) {
        return std::unexpected(NoPrune{"no authenticated commit timestamp"});
    }

    std::unordered_map<std::string, std::uint64_t> shortest_depth;
    std::vector<std::string> queue = heads;
    for (const auto& h : heads) {
        shortest_depth[h] = 0;
    }

    std::size_t head_ptr = 0;
    while (head_ptr < queue.size()) {
        const auto current_id = queue[head_ptr++];
        const auto depth = shortest_depth[current_id];
        auto it = by_id.find(current_id);
        if (it != by_id.end()) {
            for (const auto& p : it->second->commit.parents) {
                if (!shortest_depth.contains(p) ||
                    shortest_depth[p] > depth + 1) {
                    shortest_depth[p] = depth + 1;
                    queue.push_back(p);
                }
            }
        }
    }

    std::unordered_set<std::string> prunable;
    const auto age_limit_seconds =
        static_cast<std::int64_t>(policy.min_history_age_hours) * 3600LL;
    for (const auto& c : commits) {
        if (shortest_depth.contains(c.id)) {
            const auto depth = shortest_depth[c.id];
            if (depth >= policy.min_history_depth && c.commit.created_at > 0 &&
                c.commit.created_at <= newest_authenticated_head &&
                newest_authenticated_head - c.commit.created_at >=
                    age_limit_seconds) {
                prunable.insert(c.id);
            }
        }
    }

    std::vector<Anchor> anchors;
    for (const auto& c : commits) {
        if (!prunable.contains(c.id)) {
            for (const auto& p : c.commit.parents) {
                if (prunable.contains(p)) {
                    auto parent_it = by_id.find(p);
                    if (parent_it != by_id.end()) {
                        anchors.push_back(
                            Anchor{.commit_id = p,
                                   .height = parent_it->second->commit.height});
                    }
                }
            }
        }
    }

    if (prunable.empty()) {
        return std::unexpected(NoPrune{"no commits reached retention limits"});
    }

    std::vector<std::string> pruned_list;
    for (const auto& id : prunable)
        pruned_list.push_back(id);
    std::ranges::sort(pruned_list);

    std::ranges::sort(anchors, [](const Anchor& a, const Anchor& b) {
        return a.commit_id < b.commit_id;
    });
    auto last =
        std::ranges::unique(anchors, [](const Anchor& a, const Anchor& b) {
            return a.commit_id == b.commit_id;
        });
    anchors.erase(last.begin(), last.end());

    return EpochPlan{.anchors = anchors, .prunable_commits = pruned_list};
}

} // namespace kasumi::application::history_storage::epoch
