#include "application/history_storage/epoch.hpp"

#include "application/history_storage/commit_cache.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/wire.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <exception>
#include <limits>
#include <map>
#include <monocypher.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace kasumi::application::history_storage::epoch {

namespace {

inline constexpr std::array<std::byte, 4> epoch_magic{
    std::byte{'K'}, std::byte{'E'}, std::byte{'P'}, std::byte{'O'}};
inline constexpr std::array<std::uint8_t, 5> envelope_header{
    'K', 'E', 'P', 'A', 1};
inline constexpr std::uint8_t format_version = 1;
inline constexpr std::size_t mac_size = 16;
inline constexpr std::size_t nonce_size = 24;

Error error(ErrorCode code, std::string detail) {
    return Error{.code = code, .detail = std::move(detail)};
}

bool valid_id(std::string_view value) noexcept {
    return history::valid_commit_id(value);
}

template <typename Fn> auto guard_alloc(Fn&& fn) -> decltype(fn()) {
    try {
        return std::forward<Fn>(fn)();
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
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
    std::memcpy(nonce.data(), identifier.data(), nonce.size());
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
            if (identifier.starts_with(layout.epochs_prefix)) {
                identifiers.push_back(identifier);
            }
        }
    } else {
        auto listed = detail::list_identifiers(storage, layout.epochs_prefix);
        if (!listed) {
            return std::unexpected(
                error(ErrorCode::TransportFailure, listed.error().detail));
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
                return std::unexpected(error(
                    ErrorCode::Conflict,
                    "epoch sequence " + std::to_string(reference->sequence) +
                        " has multiple identifiers"));
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
                     std::size_t request_index,
                     CommitCache* commit_cache = nullptr) {
    if (commit_cache != nullptr) {
        if (auto cached = lookup_cached_epoch(
                *commit_cache, layout.epochs_prefix, reference)) {
            return *cached;
        }
        if (auto sealed = read_cached_sealed_epoch(
                *commit_cache, layout.epochs_prefix, reference)) {
            auto opened = open(*sealed, reference, master_key);
            if (opened) {
                store_cached_epoch(
                    *commit_cache, layout.epochs_prefix, *opened, nullptr);
                return *opened;
            }
            evict_cached_epoch(*commit_cache, layout.epochs_prefix, reference);
        }
    }
    auto identifier = object_identifier(layout, reference);
    if (!identifier) {
        return std::unexpected(identifier.error());
    }
    const auto copy =
        temporary->workspace.root / ("epoch-" + std::to_string(request_index));
    auto downloaded = detail::download(storage, *identifier, copy);
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
    auto opened = open(*bytes, reference, master_key);
    if (opened && commit_cache != nullptr) {
        store_cached_epoch(
            *commit_cache, layout.epochs_prefix, *opened, &copy);
    }
    return opened;
}

LatestResult
load_latest_impl(transport::Transport& storage,
                 std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
                 const std::filesystem::path& workspace_root,
                 std::optional<std::span<const std::string>> known_identifiers,
                 std::optional<Reference> trusted_ancestor,
                 CommitCache* commit_cache) {
    return guard_alloc([&]() -> LatestResult {
        const auto layout = derive_remote_layout(master_key);
        auto inventory =
            discover_epoch_inventory(storage, layout, known_identifiers);
        if (!inventory) {
            return std::unexpected(inventory.error());
        }
        if (inventory->references.empty()) {
            if (trusted_ancestor) {
                return std::unexpected(error(
                    ErrorCode::Conflict,
                    "remote Epoch chain is missing the local checkpoint"));
            }
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
                                           request_index++,
                                           commit_cache);
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
                return std::unexpected(
                    error(ErrorCode::Conflict,
                          "epoch ancestry has invalid predecessor"));
            }
            --index;
            auto previous = load_exact_reference(storage,
                                                 layout,
                                                 master_key,
                                                 *temporary,
                                                 inventory->references[index],
                                                 request_index++,
                                                 commit_cache);
            if (!previous) {
                return std::unexpected(previous.error());
            }
            if (previous->value.vault_id != contract.vault_id ||
                previous->value.policy != contract.policy) {
                return std::unexpected(error(
                    ErrorCode::Conflict,
                    "epoch ancestry diverges from authenticated contract"));
            }
            current = std::move(*previous);
        }
        if (trusted_ancestor && current.reference != *trusted_ancestor) {
            return std::unexpected(
                error(ErrorCode::Conflict,
                      "ancestry does not reach exact checkpoint"));
        }
        return std::optional<VerifiedEpoch>{std::move(*latest)};
    });
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

std::expected<Reference, Error>
parse_object_identifier(const RemoteLayout& layout,
                        std::string_view identifier) {
    auto parsed = parse_epoch_object(layout, identifier);
    if (!parsed) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid epoch object name"));
    }
    return *parsed;
}

std::expected<VerifiedEpoch, Error>
select_latest(std::span<const VerifiedEpoch> epochs) {
    if (epochs.empty()) {
        return std::unexpected(
            error(ErrorCode::NotFound, "no epochs available"));
    }
    const auto& contract = epochs.front().value;
    std::map<std::uint64_t, const VerifiedEpoch*> unique;
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
            unique.emplace(candidate.reference.sequence, &candidate);
        if (!inserted && candidate != *known->second) {
            return std::unexpected(
                error(ErrorCode::Conflict, "epoch sequence has conflict"));
        }
    }
    if (unique.begin()->first != 0) {
        return std::unexpected(
            error(ErrorCode::Conflict, "epoch chain missing genesis"));
    }
    auto previous = unique.begin();
    for (auto current = std::next(previous); current != unique.end();
         previous = current++) {
        if (previous->first == std::numeric_limits<std::uint64_t>::max()) {
            return std::unexpected(error(
                ErrorCode::Conflict, "epoch chain exceeds maximum sequence"));
        }
        if (current->first != previous->first + 1 ||
            current->second->value.previous_epoch_id !=
                previous->second->reference.epoch_id) {
            return std::unexpected(
                error(ErrorCode::Conflict, "epoch chain has discontinuity"));
        }
    }
    return *unique.rbegin()->second;
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
    const auto source = (*temporary)->workspace.root / "epoch.source";
    if (auto written = detail::write_file(source, sealed.bytes); !written) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, written.error().detail));
    }
    if (auto uploaded = transport::put(storage, source, *identifier);
        !uploaded) {
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
verify(transport::Transport& storage,
       const Epoch& expected,
       const Reference& reference,
       std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
       const std::filesystem::path& workspace_root) {
    const auto layout = derive_remote_layout(master_key);
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, temporary.error().detail));
    }
    auto verified = load_exact_reference(
        storage, layout, master_key, *temporary, reference, 0);
    if (!verified) {
        if (verified.error().code == ErrorCode::TransportFailure ||
            verified.error().code == ErrorCode::WorkspaceFailure ||
            verified.error().code == ErrorCode::InvalidInput) {
            return std::unexpected(verified.error());
        }
        return std::unexpected(
            error(ErrorCode::VerificationFailure, verified.error().detail));
    }
    if (verified->value != expected) {
        return std::unexpected(error(ErrorCode::VerificationFailure,
                                     "remote epoch diverges from expected"));
    }
    return {};
}

LatestResult
load_latest(transport::Transport& storage,
            std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
            const std::filesystem::path& workspace_root,
            std::optional<Reference> trusted_ancestor,
            CommitCache* commit_cache) {
    return load_latest_impl(storage,
                            master_key,
                            workspace_root,
                            std::nullopt,
                            std::move(trusted_ancestor),
                            commit_cache);
}

LatestResult
load_latest(transport::Transport& storage,
            std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
            const std::filesystem::path& workspace_root,
            std::span<const std::string> identifiers,
            std::optional<Reference> trusted_ancestor,
            CommitCache* commit_cache) {
    return load_latest_impl(storage,
                            master_key,
                            workspace_root,
                            identifiers,
                            std::move(trusted_ancestor),
                            commit_cache);
}

ChainResult
load_chain(transport::Transport& storage,
           std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
           const std::filesystem::path& workspace_root) {
    return guard_alloc([&] {
        return load_chain_impl(
            storage, master_key, workspace_root, std::nullopt);
    });
}

ChainResult
load_chain(transport::Transport& storage,
           std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
           const std::filesystem::path& workspace_root,
           std::span<const std::string> identifiers) {
    return guard_alloc([&] {
        return load_chain_impl(
            storage, master_key, workspace_root, identifiers);
    });
}

LatestResult
load_by_id(transport::Transport& storage,
           std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
           const std::filesystem::path& workspace_root,
           std::string_view epoch_id) {
    return guard_alloc([&]() -> LatestResult {
        if (!valid_id(epoch_id)) {
            return std::unexpected(
                error(ErrorCode::InvalidInput, "invalid epoch ID"));
        }

        const auto layout = derive_remote_layout(master_key);
        auto listed = detail::list_identifiers(storage, layout.epochs_prefix);
        if (!listed) {
            return std::unexpected(
                error(ErrorCode::TransportFailure, listed.error().detail));
        }
        std::optional<Reference> matching;
        for (const auto& name : *listed) {
            const auto identifier = name.starts_with(layout.epochs_prefix)
                                        ? name
                                        : layout.epochs_prefix + name;
            auto reference = parse_object_identifier(layout, identifier);
            if (!reference) {
                return std::unexpected(reference.error());
            }
            if (reference->epoch_id == epoch_id) {
                if (matching && matching->sequence != reference->sequence) {
                    return std::unexpected(error(
                        ErrorCode::Conflict,
                        "epoch identifier appears in multiple sequences"));
                }
                matching = *reference;
            }
        }
        if (!matching) {
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
    });
}

PruneResult plan_pruning(std::span<const kasumi::history::LoadedCommit> commits,
                         const RetentionPolicy& policy,
                         const PruneOptions& options) {
    if (commits.size() > kasumi::history::maximum_loaded_commit_count) {
        return std::unexpected(NoPrune{"defensive limit exceeded"});
    }
    if (policy.min_history_depth == 0 ||
        policy.min_history_depth > kasumi::history::maximum_graph_depth ||
        policy.min_history_age_hours == 0) {
        return std::unexpected(NoPrune{"invalid retention policy"});
    }
    if (commits.empty()) {
        return std::unexpected(NoPrune{"no commits reached retention limits"});
    }

    std::unordered_map<std::string_view, const kasumi::history::LoadedCommit*>
        by_id;
    std::unordered_map<std::string_view,
                       std::vector<const kasumi::history::LoadedCommit*>>
        children_by_id;
    by_id.reserve(commits.size());
    children_by_id.reserve(commits.size());
    for (const auto& c : commits) {
        by_id[c.id] = &c;
        for (const auto& p : c.commit.parents) {
            children_by_id[p].push_back(&c);
        }
    }

    std::vector<std::string_view> logical_heads;
    std::int64_t newest_authenticated_head = 0;
    for (const auto& c : commits) {
        for (const auto& parent : c.commit.parents) {
            if (const auto it = by_id.find(parent);
                it != by_id.end() &&
                it->second->commit.created_at > c.commit.created_at) {
                return std::unexpected(
                    NoPrune{"timestamp regression detected"});
            }
        }
        if (const auto child_it = children_by_id.find(c.id);
            child_it == children_by_id.end() || child_it->second.empty()) {
            newest_authenticated_head =
                std::max(newest_authenticated_head, c.commit.created_at);
            logical_heads.push_back(c.id);
        }
    }
    if (newest_authenticated_head <= 0) {
        return std::unexpected(NoPrune{"no authenticated commit timestamp"});
    }
    std::int64_t effective_now = newest_authenticated_head;
    if (options.reference_now_unix.has_value()) {
        if (*options.reference_now_unix <= 0) {
            return std::unexpected(NoPrune{"no trusted reference clock"});
        }
        effective_now = *options.reference_now_unix;
    }

    std::unordered_set<std::string_view> marked_set;
    marked_set.reserve(options.marked_commit_ids.size());
    for (const auto& id : options.marked_commit_ids) {
        if (by_id.contains(id)) {
            marked_set.insert(id);
        }
    }
    std::unordered_set<std::string_view> protected_set;
    protected_set.reserve(options.protected_commit_ids.size());
    for (const auto& id : options.protected_commit_ids) {
        if (by_id.contains(id)) {
            protected_set.insert(id);
        }
    }
    std::unordered_set<std::string_view> current_anchor_set;
    current_anchor_set.reserve(options.current_anchors.size());
    for (const auto& anchor : options.current_anchors) {
        if (by_id.contains(anchor.commit_id)) {
            current_anchor_set.insert(anchor.commit_id);
        }
    }

    // Shortest distance (in edges) from any logical head or marked commit.
    std::unordered_map<std::string_view, std::uint64_t> shortest_depth;
    shortest_depth.reserve(commits.size());
    std::vector<const kasumi::history::LoadedCommit*> queue;
    queue.reserve(commits.size());
    const auto seed_root = [&](std::string_view root_id) {
        if (auto [it, inserted] = shortest_depth.try_emplace(root_id, 0);
            inserted) {
            if (const auto found = by_id.find(root_id); found != by_id.end()) {
                queue.push_back(found->second);
            }
        }
    };
    for (const auto head_id : logical_heads) {
        seed_root(head_id);
    }
    for (const auto marked_id : marked_set) {
        seed_root(marked_id);
    }
    for (std::size_t head_ptr = 0; head_ptr < queue.size(); ++head_ptr) {
        const auto* current = queue[head_ptr];
        const auto next_depth = shortest_depth[current->id] + 1;
        for (const auto& p : current->commit.parents) {
            if (auto [it, inserted] = shortest_depth.try_emplace(p, next_depth);
                inserted || it->second > next_depth) {
                it->second = next_depth;
                if (const auto parent_it = by_id.find(p);
                    parent_it != by_id.end()) {
                    queue.push_back(parent_it->second);
                }
            }
        }
    }

    // Protect the full merge-base closure when multiple unreconciled logical
    // heads exist so branches can always reconcile without losing common roots.
    std::unordered_set<std::string_view> merge_closure;
    if (logical_heads.size() > 1) {
        const auto collect_ancestors = [&](std::string_view start) {
            std::unordered_set<std::string_view> visited;
            std::vector<std::string_view> stack{start};
            visited.insert(start);
            while (!stack.empty()) {
                const auto cur = stack.back();
                stack.pop_back();
                const auto found = by_id.find(cur);
                if (found == by_id.end()) {
                    continue;
                }
                for (const auto& parent : found->second->commit.parents) {
                    if (by_id.contains(parent) &&
                        visited.insert(parent).second) {
                        stack.push_back(parent);
                    }
                }
            }
            return visited;
        };

        std::vector<std::string_view> bases = logical_heads;
        std::ranges::sort(bases);
        bases.erase(std::ranges::unique(bases).begin(), bases.end());
        std::size_t ancestor_visits = 0;
        std::size_t layer_count = 0;
        while (bases.size() > 1) {
            if (bases.size() > kasumi::history::maximum_parent_count ||
                layer_count >= kasumi::history::maximum_graph_depth) {
                return std::unexpected(
                    NoPrune{"virtual merge base limit exceeded"});
            }
            ++layer_count;
            std::unordered_set<std::string_view> common;
            for (std::size_t i = 0; i < bases.size(); ++i) {
                auto ancestors = collect_ancestors(bases[i]);
                ancestor_visits += ancestors.size();
                if (ancestor_visits >
                    kasumi::history::maximum_virtual_base_ancestor_visits) {
                    return std::unexpected(
                        NoPrune{"virtual merge base limit exceeded"});
                }
                if (i == 0) {
                    common = std::move(ancestors);
                } else {
                    std::erase_if(common, [&](std::string_view id) {
                        return !ancestors.contains(id);
                    });
                }
            }
            if (common.empty()) {
                return std::unexpected(
                    NoPrune{"cannot prune across disconnected branch roots"});
            }
            std::unordered_set<std::string_view> dominated;
            for (const auto candidate : common) {
                const auto found = by_id.find(candidate);
                if (found == by_id.end()) {
                    continue;
                }
                std::vector<std::string_view> walk;
                for (const auto& p : found->second->commit.parents) {
                    if (common.contains(p) && dominated.insert(p).second) {
                        walk.push_back(p);
                    }
                }
                while (!walk.empty()) {
                    const auto cur = walk.back();
                    walk.pop_back();
                    const auto cur_it = by_id.find(cur);
                    if (cur_it == by_id.end()) {
                        continue;
                    }
                    for (const auto& p : cur_it->second->commit.parents) {
                        if (common.contains(p) && dominated.insert(p).second) {
                            walk.push_back(p);
                        }
                    }
                }
            }
            std::vector<std::string_view> next_bases;
            for (const auto candidate : common) {
                if (!dominated.contains(candidate)) {
                    next_bases.push_back(candidate);
                }
            }
            if (next_bases.empty()) {
                return std::unexpected(
                    NoPrune{"cannot prune across disconnected branch roots"});
            }
            std::ranges::sort(next_bases);
            bases = std::move(next_bases);
        }

        const auto common_root = bases.front();
        std::unordered_set<std::string_view> from_heads;
        std::vector<std::string_view> up_stack = logical_heads;
        for (const auto h : up_stack) {
            from_heads.insert(h);
        }
        while (!up_stack.empty()) {
            const auto cur = up_stack.back();
            up_stack.pop_back();
            if (cur == common_root) {
                continue;
            }
            const auto found = by_id.find(cur);
            if (found == by_id.end()) {
                continue;
            }
            for (const auto& p : found->second->commit.parents) {
                if (by_id.contains(p) && from_heads.insert(p).second) {
                    up_stack.push_back(p);
                }
            }
        }
        std::vector<std::string_view> down_stack{common_root};
        merge_closure.insert(common_root);
        while (!down_stack.empty()) {
            const auto cur = down_stack.back();
            down_stack.pop_back();
            const auto child_it = children_by_id.find(cur);
            if (child_it == children_by_id.end()) {
                continue;
            }
            for (const auto* child : child_it->second) {
                if (from_heads.contains(child->id) &&
                    merge_closure.insert(child->id).second) {
                    down_stack.push_back(child->id);
                }
            }
        }
    }

    std::unordered_set<std::string_view> prunable;
    const auto age_limit_seconds =
        static_cast<std::int64_t>(policy.min_history_age_hours) * 3600LL;
    for (const auto& c : commits) {
        if (merge_closure.contains(c.id) || protected_set.contains(c.id) ||
            marked_set.contains(c.id)) {
            continue;
        }
        const auto depth_it = shortest_depth.find(c.id);
        if (depth_it == shortest_depth.end() ||
            depth_it->second < policy.min_history_depth) {
            continue;
        }
        const auto child_it = children_by_id.find(c.id);
        if (child_it == children_by_id.end() || child_it->second.empty()) {
            continue;
        }
        if (c.commit.created_at <= 0) {
            continue;
        }
        std::int64_t superseded_at = 0;
        bool valid_children_time = true;
        for (const auto* child : child_it->second) {
            if (child->commit.created_at <= 0) {
                valid_children_time = false;
                break;
            }
            superseded_at = std::max(superseded_at, child->commit.created_at);
        }
        if (!valid_children_time || superseded_at > effective_now ||
            (effective_now - superseded_at) < age_limit_seconds) {
            continue;
        }
        prunable.insert(c.id);
    }
    if (prunable.empty()) {
        return std::unexpected(NoPrune{"no commits reached retention limits"});
    }

    // Walk from logical heads and marked commits to build a reachable boundary
    // anchor set; every non-retained commit lies strictly behind these anchors.
    std::unordered_set<std::string_view> retained;
    std::map<std::string_view, std::uint64_t> anchor_heights;
    std::vector<std::string_view> frontier_walk;
    for (const auto head_id : logical_heads) {
        if (retained.insert(head_id).second) {
            frontier_walk.push_back(head_id);
        }
    }
    for (const auto marked_id : marked_set) {
        if (retained.insert(marked_id).second) {
            frontier_walk.push_back(marked_id);
        }
    }
    while (!frontier_walk.empty()) {
        const auto cur_id = frontier_walk.back();
        frontier_walk.pop_back();
        const auto cur_it = by_id.find(cur_id);
        if (cur_it == by_id.end()) {
            continue;
        }
        const auto& cur = *cur_it->second;
        if (current_anchor_set.contains(cur.id)) {
            anchor_heights.emplace(cur.id, cur.commit.height);
            continue;
        }
        const bool all_parents_prunable =
            !cur.commit.parents.empty() &&
            std::ranges::all_of(cur.commit.parents, [&](std::string_view p) {
                return prunable.contains(p);
            });
        if (all_parents_prunable) {
            anchor_heights.emplace(cur.id, cur.commit.height);
            continue;
        }
        for (const auto& p : cur.commit.parents) {
            if (prunable.contains(p)) {
                if (const auto parent_it = by_id.find(p);
                    parent_it != by_id.end()) {
                    retained.insert(p);
                    anchor_heights.emplace(p, parent_it->second->commit.height);
                }
            } else if (by_id.contains(p) && retained.insert(p).second) {
                frontier_walk.push_back(p);
            }
        }
    }

    EpochPlan plan;
    for (const auto& c : commits) {
        if (!retained.contains(c.id)) {
            plan.prunable_commits.push_back(c.id);
        }
    }
    if (plan.prunable_commits.empty() || anchor_heights.empty()) {
        return std::unexpected(NoPrune{"no commits reached retention limits"});
    }
    if (anchor_heights.size() > maximum_anchor_count) {
        return std::unexpected(
            NoPrune{"planned anchor count exceeds epoch limit"});
    }
    std::ranges::sort(plan.prunable_commits);
    plan.anchors.reserve(anchor_heights.size());
    for (const auto& [id, height] : anchor_heights) {
        plan.anchors.push_back(
            Anchor{.commit_id = std::string{id}, .height = height});
    }
    return plan;
}

} // namespace kasumi::application::history_storage::epoch
