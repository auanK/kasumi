#include "application/history_storage/history_storage.hpp"

#include "application/history_storage/detail.hpp"
#include "core/wire.hpp"

#include <array>

namespace kasumi::application::history_storage {

using namespace detail;

bool valid(const HeadReference& reference) noexcept {
    return valid_hex_id(reference.commit_id) &&
           valid_hex_id(reference.ciphertext_id);
}

MarkerResult encode_marker(const HeadReference& reference) {
    if (!valid(reference)) {
        return std::unexpected(
            error(ErrorCode::InvalidIdentifier, "invalid head reference"));
    }
    auto commit_hash = hash_from_hex(reference.commit_id);
    auto ciphertext_hash = hash_from_hex(reference.ciphertext_id);
    if (!commit_hash || !ciphertext_hash) {
        return std::unexpected(
            error(ErrorCode::InvalidIdentifier, "invalid head reference"));
    }

    wire::Writer writer;
    wire::write_array(
        writer,
        std::array<std::byte, 4>{
            std::byte{'K'}, std::byte{'H'}, std::byte{'E'}, std::byte{'D'}});
    wire::write(writer, static_cast<std::uint8_t>(2));
    wire::write_array(writer, *commit_hash);
    wire::write_array(writer, *ciphertext_hash);
    if (writer.buffer.size() != marker_size) {
        return std::unexpected(
            error(ErrorCode::InvalidMarker, "invalid marker size"));
    }
    std::vector<std::uint8_t> result(writer.buffer.size());
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(writer.buffer[index]);
    }
    return result;
}

std::expected<HeadReference, Error>
decode_marker(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != marker_size) {
        return std::unexpected(
            error(ErrorCode::InvalidMarker, "marker size is invalid"));
    }
    std::span<const std::byte> data(
        reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
    wire::Reader reader{data};
    auto magic = wire::read_array<4>(reader);
    auto version = wire::read<std::uint8_t>(reader);
    if (!magic || !version ||
        *magic != std::array<std::byte, 4>{std::byte{'K'},
                                           std::byte{'H'},
                                           std::byte{'E'},
                                           std::byte{'D'}} ||
        *version != 2) {
        return std::unexpected(
            error(ErrorCode::InvalidMarker, "marker header is invalid"));
    }
    auto commit_bytes = wire::read_array<32>(reader);
    auto ciphertext_bytes = wire::read_array<32>(reader);
    if (!commit_bytes || !ciphertext_bytes || !reader.data.empty()) {
        return std::unexpected(
            error(ErrorCode::InvalidMarker, "marker payload is invalid"));
    }

    Hash commit_hash;
    Hash ciphertext_hash;
    for (std::size_t index = 0; index < HASH_SIZE; ++index) {
        commit_hash[index] = (*commit_bytes)[index];
        ciphertext_hash[index] = (*ciphertext_bytes)[index];
    }
    HeadReference result{.commit_id = hash_hex(commit_hash),
                         .ciphertext_id = hash_hex(ciphertext_hash)};
    if (!valid(result)) {
        return std::unexpected(
            error(ErrorCode::InvalidMarker, "marker IDs are invalid"));
    }
    return result;
}

InspectCommitVariantsResult
inspect_commit_variants(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        std::string_view commit_id,
                        const std::filesystem::path& workspace_root,
                        std::optional<HeadReference> authenticated_variant) {
    try {
        if (!transport::valid(storage) || !valid_hex_id(commit_id) ||
            (authenticated_variant &&
             (!valid(*authenticated_variant) ||
              authenticated_variant->commit_id != commit_id))) {
            return std::unexpected(
                error(ErrorCode::InvalidInput, "invalid commit inspection"));
        }
        auto temporary = make_workspace(workspace_root);
        if (!temporary) {
            return std::unexpected(temporary.error());
        }

        const auto prefix = std::string{commit_prefix} + std::string{commit_id};
        auto listed = transport::list(storage, prefix);
        if (!listed) {
            if (listed.error().code == transport::ErrorCode::StorageNotFound) {
                return std::vector<PhysicalCommitVariant>{};
            }
            return std::unexpected(transport_error(listed.error()));
        }

        std::vector<HeadReference> references;
        references.reserve(listed->size());
        for (const auto& name : *listed) {
            auto reference = parse_commit_object(prefix + "/" + name);
            if (reference && reference->commit_id == commit_id) {
                references.push_back(std::move(*reference));
            }
        }
        sort_unique(references);
        if (references.size() > maximum_ciphertext_variants_per_commit) {
            return std::unexpected(error(ErrorCode::LimitExceeded,
                                         "too many ciphertext variants"));
        }

        std::vector<PhysicalCommitVariant> result;
        result.reserve(references.size());
        std::size_t sequence = 0;
        for (const auto& reference : references) {
            if (authenticated_variant && reference == *authenticated_variant) {
                result.push_back(PhysicalCommitVariant{
                    .reference = reference,
                    .identifier = commit_object(reference),
                    .state = PhysicalCommitVariantState::Valid,
                });
                continue;
            }
            auto loaded = try_load_variant(
                storage, key, reference, (*temporary)->root, sequence++);
            if (!loaded) {
                return std::unexpected(loaded.error());
            }
            if (loaded->state == VariantState::Missing) {
                continue;
            }
            const auto state =
                loaded->state == VariantState::Valid
                    ? PhysicalCommitVariantState::Valid
                : loaded->state == VariantState::InvalidCommit
                    ? PhysicalCommitVariantState::InvalidCommit
                    : PhysicalCommitVariantState::InvalidCiphertext;
            result.push_back(PhysicalCommitVariant{
                .reference = reference,
                .identifier = commit_object(reference),
                .state = state,
            });
        }
        return result;
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

PublishResult
publish_commit(transport::Transport& storage,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               const history::Commit& commit,
               const std::filesystem::path& workspace_root) {
    try {
        return publish_impl(storage, key, commit, workspace_root);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

LoadResult load_history(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const std::filesystem::path& workspace_root) {
    try {
        return load_impl(storage, key, workspace_root);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

LoadResult load_history(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const std::filesystem::path& workspace_root,
                        const KnownHistoryFrontier& frontier) {
    try {
        return detail::load_impl(
            storage, key, workspace_root, std::nullopt, &frontier);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

LoadResult load_history(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const std::filesystem::path& workspace_root,
                        std::span<const std::string> identifiers) {
    try {
        return detail::load_impl(storage, key, workspace_root, identifiers);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

LoadResult load_history(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const std::filesystem::path& workspace_root,
                        std::span<const std::string> identifiers,
                        const KnownHistoryFrontier& frontier) {
    try {
        return detail::load_impl(
            storage, key, workspace_root, identifiers, &frontier);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

LoadResult
load_history_scoped(transport::Transport& storage,
                    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                    const std::filesystem::path& workspace_root,
                    const KnownHistoryFrontier* frontier,
                    std::span<const std::string> trusted_marker_identifiers) {
    try {
        return detail::load_impl(storage,
                                 key,
                                 workspace_root,
                                 std::nullopt,
                                 frontier,
                                 true,
                                 trusted_marker_identifiers);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

} // namespace kasumi::application::history_storage
