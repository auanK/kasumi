#include "application/history_storage/detail.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <fstream>
#include <limits>
#include <system_error>
#include <utility>

namespace kasumi::application::history_storage::detail {

std::expected<std::vector<std::uint8_t>, Error>
read_file(const std::filesystem::path& path, std::size_t maximum_size) {
    std::error_code filesystem_error;
    const auto size = std::filesystem::file_size(path, filesystem_error);
    if (filesystem_error) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, filesystem_error.message()));
    }
    if (size > maximum_size || size > std::numeric_limits<std::size_t>::max()) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "temporary file exceeds limit"));
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected(error(ErrorCode::WorkspaceFailure,
                                     "could not open temporary file"));
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    if (!input ||
        input.gcount() != static_cast<std::streamsize>(bytes.size())) {
        return std::unexpected(error(ErrorCode::WorkspaceFailure,
                                     "could not read temporary file"));
    }
    return bytes;
}

std::expected<void, Error> write_file(const std::filesystem::path& path,
                                      std::span<const std::uint8_t> bytes) {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    auto created = platform::private_storage::create_file(path);
    if (!created) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, created.error()));
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return std::unexpected(error(ErrorCode::WorkspaceFailure,
                                     "could not create temporary file"));
    }
    if (!bytes.empty()) {
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
    }
    if (!output) {
        return std::unexpected(error(ErrorCode::WorkspaceFailure,
                                     "could not write temporary file"));
    }
    return {};
}

void remove_file(const std::filesystem::path& path) noexcept {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

void remove_workspace(TemporaryWorkspaceData* workspace) noexcept {
    const auto trace = platform::perf_trace::begin();
    if (workspace != nullptr && !workspace->root.empty()) {
        platform::cleanup_workspace(platform::Workspace{workspace->root});
    }
    delete workspace;
    platform::perf_trace::finish("workspace cleanup", trace);
}

std::expected<TemporaryWorkspace, Error>
make_workspace(const std::filesystem::path& root) {
    std::error_code filesystem_error;
    if (root.empty() ||
        !std::filesystem::is_directory(root, filesystem_error) ||
        filesystem_error) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, "workspace root is invalid"));
    }

    for (std::size_t attempt = 0; attempt < 16; ++attempt) {
        auto id = platform::random::hex_id();
        if (!id) {
            return std::unexpected(
                error(ErrorCode::WorkspaceFailure, id.error()));
        }
        const auto candidate = root / (".kasumi-history-" + *id);
        auto created = platform::private_storage::create_directory(candidate);
        if (created) {
            return TemporaryWorkspace{new TemporaryWorkspaceData{candidate},
                                      remove_workspace};
        }
        filesystem_error.clear();
        if (!std::filesystem::exists(candidate, filesystem_error) ||
            filesystem_error) {
            return std::unexpected(
                error(ErrorCode::WorkspaceFailure, created.error()));
        }
    }
    return std::unexpected(error(ErrorCode::WorkspaceFailure,
                                 "could not create isolated workspace"));
}

std::expected<void, Error> download(transport::Transport& storage,
                                    std::string_view identifier,
                                    const std::filesystem::path& destination) {
    remove_file(destination);
    auto result = transport::get(storage, identifier, destination);
    if (!result) {
        return std::unexpected(transport_error(result.error()));
    }
    auto secured = platform::private_storage::protect_file(destination);
    if (!secured) {
        remove_file(destination);
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, secured.error()));
    }
    return {};
}

std::expected<void, Error>
download_commit_candidate(transport::Transport& storage,
                          const HeadReference& reference,
                          const std::filesystem::path& destination) {
    remove_file(destination);
    const auto get_trace = platform::perf_trace::begin();
    auto result =
        transport::get(storage, commit_object(reference), destination);
    platform::perf_trace::finish("rc/get_commit", get_trace);
    if (!result) {
        if (result.error().code == transport::ErrorCode::ObjectNotFound) {
            return std::unexpected(
                error(ErrorCode::MissingCommit, "commit object is missing"));
        }
        return std::unexpected(transport_error(result.error()));
    }
    return {};
}

std::expected<MarkerState, Error>
inspect_marker(transport::Transport& storage,
               const HeadReference& reference,
               const std::filesystem::path& workspace,
               std::size_t& sequence) {
    const auto path =
        workspace / ("marker-inspect-" + std::to_string(sequence++));
    remove_file(path);
    const auto get_trace = platform::perf_trace::begin();
    const auto fetched =
        transport::get(storage, marker_object(reference), path);
    platform::perf_trace::finish("rc/get_marker", get_trace);
    if (!fetched) {
        remove_file(path);
        if (fetched.error().code == transport::ErrorCode::ObjectNotFound) {
            return MarkerState::Absent;
        }
        return std::unexpected(transport_error(fetched.error()));
    }

    auto bytes = read_file(path, marker_size);
    remove_file(path);
    if (!bytes) {
        if (bytes.error().code == ErrorCode::LimitExceeded) {
            return MarkerState::Invalid;
        }
        return std::unexpected(bytes.error());
    }
    if (bytes->size() != marker_size) {
        return MarkerState::Invalid;
    }
    const auto decoded = decode_marker(*bytes);
    return decoded && *decoded == reference ? MarkerState::Valid
                                            : MarkerState::Invalid;
}

std::expected<bool, Error> ciphertext_matches(const std::filesystem::path& path,
                                              std::string_view ciphertext_id) {
    if (!valid_hex_id(ciphertext_id)) {
        return std::unexpected(error(ErrorCode::InvalidIdentifier,
                                     "invalid ciphertext identifier"));
    }

    std::error_code filesystem_error;
    const auto status = std::filesystem::symlink_status(path, filesystem_error);
    if (filesystem_error ||
        status.type() == std::filesystem::file_type::not_found ||
        std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(error(ErrorCode::WorkspaceFailure,
                                     "ciphertext is not a regular file"));
    }
    auto actual_hash = crypto::content::hash_file(path);
    if (!actual_hash) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, actual_hash.error()));
    }
    return hash_hex(*actual_hash) == ciphertext_id;
}

std::expected<void, Error>
validate_ciphertext_size(const std::filesystem::path& path) {
    std::error_code filesystem_error;
    const auto size = std::filesystem::file_size(path, filesystem_error);
    if (filesystem_error) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, filesystem_error.message()));
    }
    if (size > maximum_commit_ciphertext_size) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "ciphertext exceeds maximum size"));
    }
    return {};
}

VariantResult
try_load_variant(transport::Transport& storage,
                 std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                 const HeadReference& reference,
                 const std::filesystem::path& workspace,
                 std::size_t sequence) {
    auto ciphertext = workspace / reference.commit_id /
                      (reference.ciphertext_id + std::string{commit_suffix});
    std::error_code prefetched_error;
    if (!std::filesystem::is_regular_file(ciphertext, prefetched_error)) {
        ciphertext = workspace / ("ciphertext-" + std::to_string(sequence));
    }
    const auto plaintext =
        workspace / ("plaintext-" + std::to_string(sequence));
    const auto invalid_ciphertext = [&]() -> VariantResult {
        remove_file(ciphertext);
        remove_file(plaintext);
        return LoadedVariant{.state = VariantState::InvalidCiphertext,
                             .commit = std::nullopt};
    };
    const auto invalid_commit = [&]() -> VariantResult {
        remove_file(ciphertext);
        remove_file(plaintext);
        return LoadedVariant{.state = VariantState::InvalidCommit,
                             .commit = std::nullopt};
    };

    if (!std::filesystem::is_regular_file(ciphertext, prefetched_error)) {
        auto downloaded =
            download_commit_candidate(storage, reference, ciphertext);
        if (!downloaded) {
            if (downloaded.error().code == ErrorCode::MissingCommit) {
                remove_file(ciphertext);
                remove_file(plaintext);
                return LoadedVariant{.state = VariantState::Missing,
                                     .commit = std::nullopt};
            }
            remove_file(ciphertext);
            remove_file(plaintext);
            return std::unexpected(downloaded.error());
        }
    }
    auto size_valid = validate_ciphertext_size(ciphertext);
    if (!size_valid) {
        if (size_valid.error().code == ErrorCode::LimitExceeded) {
            return invalid_ciphertext();
        }
        remove_file(ciphertext);
        remove_file(plaintext);
        return std::unexpected(size_valid.error());
    }
    auto matches = ciphertext_matches(ciphertext, reference.ciphertext_id);
    if (!matches) {
        remove_file(ciphertext);
        remove_file(plaintext);
        return std::unexpected(matches.error());
    }
    if (!*matches ||
        !crypto::decrypt_file(
            ciphertext, plaintext, key, crypto::FilePurpose::History)) {
        return invalid_ciphertext();
    }

    auto bytes = read_file(plaintext, history::maximum_commit_plaintext_size);
    if (!bytes) {
        if (bytes.error().code == ErrorCode::LimitExceeded) {
            return invalid_commit();
        }
        remove_file(ciphertext);
        remove_file(plaintext);
        return std::unexpected(bytes.error());
    }
    auto commit = history::deserialize(*bytes);
    if (!commit) {
        return invalid_commit();
    }
    auto canonical = history::serialize(*commit);
    if (!canonical) {
        return invalid_commit();
    }
    const bool valid_commit =
        crypto::commit_identifier(key, *canonical) == reference.commit_id &&
        *canonical == *bytes;
    remove_file(ciphertext);
    remove_file(plaintext);
    if (!valid_commit) {
        return LoadedVariant{.state = VariantState::InvalidCommit,
                             .commit = std::nullopt};
    }
    return LoadedVariant{
        .state = VariantState::Valid,
        .commit = history::LoadedCommit{.id = reference.commit_id,
                                        .commit = std::move(*commit)}};
}

std::expected<history::LoadedCommit, Error>
try_load_variants(transport::Transport& storage,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                  std::vector<HeadReference> references,
                  const std::filesystem::path& workspace,
                  std::size_t& sequence,
                  HeadReference* authenticated_reference) {
    if (references.empty()) {
        return std::unexpected(
            error(ErrorCode::MissingCommit, "commit object is missing"));
    }
    bool saw_invalid_ciphertext = false;
    bool saw_invalid_commit = false;
    sort_unique(references);
    for (const auto& reference : references) {
        auto loaded =
            try_load_variant(storage, key, reference, workspace, sequence++);
        if (!loaded) {
            return std::unexpected(loaded.error());
        }
        switch (loaded->state) {
            case VariantState::Missing:
                break;
            case VariantState::InvalidCiphertext:
                saw_invalid_ciphertext = true;
                break;
            case VariantState::InvalidCommit:
                saw_invalid_commit = true;
                break;
            case VariantState::Valid:
                if (loaded->commit.has_value()) {
                    if (authenticated_reference != nullptr) {
                        *authenticated_reference = reference;
                    }
                    return std::move(*loaded->commit);
                }
                saw_invalid_commit = true;
                break;
        }
    }
    if (saw_invalid_commit) {
        return std::unexpected(
            error(ErrorCode::InvalidCommit, "no valid commit variant"));
    }
    if (saw_invalid_ciphertext) {
        return std::unexpected(
            error(ErrorCode::InvalidCiphertext, "no valid ciphertext variant"));
    }
    return std::unexpected(
        error(ErrorCode::MissingCommit, "commit object is missing"));
}

std::expected<void, Error>
verify_published_commit(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const history::Commit& expected,
                        const HeadReference& reference,
                        const std::filesystem::path& workspace,
                        std::size_t& sequence) {
    auto loaded =
        try_load_variant(storage, key, reference, workspace, sequence++);
    if (!loaded) {
        return std::unexpected(loaded.error());
    }
    if (loaded->state != VariantState::Valid || !loaded->commit.has_value()) {
        return std::unexpected(error(ErrorCode::VerificationFailure,
                                     "published commit failed verification"));
    }
    auto expected_bytes = history::serialize(expected);
    auto actual_bytes = history::serialize(loaded->commit->commit);
    if (!expected_bytes || !actual_bytes || *expected_bytes != *actual_bytes) {
        return std::unexpected(error(ErrorCode::VerificationFailure,
                                     "published commit differs from input"));
    }
    return {};
}

std::expected<HistoryInventory, Error>
build_scoped_history_inventory(transport::Transport& storage) {
    auto listing = transport::list(
        storage, heads_prefix.substr(0, heads_prefix.size() - 1));
    if (!listing) {
        if (listing.error().code == transport::ErrorCode::StorageNotFound) {
            return HistoryInventory{};
        }
        return std::unexpected(transport_error(listing.error()));
    }

    HistoryInventory inventory;
    for (const auto& name : *listing) {
        const auto identifier = std::string{heads_prefix} + name;
        if (maintenance_protocol::is_control_object(identifier)) {
            continue;
        }
        auto reference = parse_marker_object(identifier);
        if (!reference) {
            continue;
        }
        inventory.identifiers.insert(identifier);
        inventory.marker_variants[reference->commit_id].push_back(
            std::move(*reference));
    }
    if (inventory.identifiers.size() > maximum_history_object_count) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "too many storage objects"));
    }
    for (auto& [unused, variants] : inventory.marker_variants) {
        static_cast<void>(unused);
        sort_unique(variants);
        if (variants.size() > maximum_ciphertext_variants_per_commit) {
            return std::unexpected(error(ErrorCode::LimitExceeded,
                                         "too many ciphertext variants"));
        }
    }
    if (inventory.marker_variants.size() > history::maximum_marked_head_count) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "too many logical heads"));
    }
    return inventory;
}

std::expected<void, Error>
discover_scoped_commit_variants(transport::Transport& storage,
                                std::string_view commit_id,
                                HistoryInventory& inventory) {
    if (!valid_hex_id(commit_id)) {
        return std::unexpected(
            error(ErrorCode::InvalidIdentifier, "invalid commit identifier"));
    }
    const auto prefix = std::string{commit_prefix} + std::string{commit_id};
    auto listing = transport::list(storage, prefix);
    if (!listing) {
        if (listing.error().code == transport::ErrorCode::StorageNotFound) {
            return {};
        }
        return std::unexpected(transport_error(listing.error()));
    }

    auto& variants = inventory.commit_variants[std::string{commit_id}];
    for (const auto& name : *listing) {
        const auto identifier = prefix + "/" + name;
        auto reference = parse_commit_object(identifier);
        if (!reference || reference->commit_id != commit_id) {
            continue;
        }
        inventory.identifiers.insert(identifier);
        variants.push_back(std::move(*reference));
    }
    sort_unique(variants);
    if (inventory.identifiers.size() > maximum_history_object_count ||
        variants.size() > maximum_ciphertext_variants_per_commit) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "history variant budget exceeded"));
    }
    return {};
}

LoadResult load_impl(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const std::filesystem::path& workspace_root,
                     std::optional<std::span<const std::string>> identifiers,
                     const KnownHistoryFrontier* frontier,
                     bool scoped,
                     std::span<const std::string> trusted_marker_identifiers) {
    if (!transport::valid(storage)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid transport"));
    }
    const bool native_complete_batch =
        !scoped && !frontier && storage.storage.get_batch != nullptr;
    std::error_code temporary_root_error;
    const auto temporary_root =
        native_complete_batch
            ? std::filesystem::temp_directory_path(temporary_root_error)
            : workspace_root;
    if (temporary_root_error) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, temporary_root_error.message()));
    }
    auto temporary = make_workspace(temporary_root);
    if (!temporary) {
        return std::unexpected(temporary.error());
    }
    const auto listing_trace = platform::perf_trace::begin();
    const auto scoped_head_trace =
        scoped ? platform::perf_trace::begin() : platform::perf_trace::Token{};
    auto inventory = [&]() {
        if (scoped) {
            return build_scoped_history_inventory(storage);
        }
        return identifiers ? build_history_inventory(*identifiers)
                           : build_history_inventory(storage);
    }();
    platform::perf_trace::finish("history listing", listing_trace);
    if (scoped) {
        platform::perf_trace::finish(trusted_marker_identifiers.empty()
                                         ? "initial head LIST"
                                         : "fresh stability LIST",
                                     scoped_head_trace);
    }
    if (!inventory) {
        return std::unexpected(inventory.error());
    }
    if (native_complete_batch) {
        transport::GetBatch batch{
            .source_prefix =
                std::string{commit_prefix.substr(0, commit_prefix.size() - 1)},
            .destination_root = (*temporary)->root,
        };
        for (const auto& [unused, references] : inventory->commit_variants) {
            static_cast<void>(unused);
            for (const auto& reference : references) {
                batch.identifiers.push_back(reference.commit_id + "/" +
                                            reference.ciphertext_id +
                                            std::string{commit_suffix});
            }
        }
        if (!batch.identifiers.empty()) {
            auto prefetched = transport::get_batch(storage, batch);
            if (!prefetched) {
                return std::unexpected(transport_error(prefetched.error()));
            }
        }
    }
    const KnownHistoryAnchor* cached_anchor = nullptr;
    if (frontier && frontier->anchors.size() > 1) {
        return std::unexpected(error(
            ErrorCode::InvalidInput,
            "local history frontier contains unsupported cached anchors"));
    }
    if (frontier && !frontier->anchors.empty()) {
        cached_anchor = &frontier->anchors.front();
    }
    if (cached_anchor && (!valid_hex_id(cached_anchor->commit_id) ||
                          !valid_snapshot(cached_anchor->tree, false))) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid history anchor"));
    }

    const auto accepted_epoch =
        frontier ? frontier->accepted_epoch : std::optional<epoch::Reference>{};
    auto discovered_epoch =
        identifiers
            ? epoch::load_latest(
                  storage, key, workspace_root, *identifiers, accepted_epoch)
            : epoch::load_latest(storage, key, workspace_root, accepted_epoch);
    if (!discovered_epoch) {
        const auto code = [&] {
            switch (discovered_epoch.error().code) {
                case epoch::ErrorCode::TransportFailure:
                    return ErrorCode::TransportFailure;
                case epoch::ErrorCode::WorkspaceFailure:
                    return ErrorCode::WorkspaceFailure;
                case epoch::ErrorCode::LimitExceeded:
                    return ErrorCode::LimitExceeded;
                default:
                    return ErrorCode::InconsistentInventory;
            }
        }();
        return std::unexpected(error(code, discovered_epoch.error().detail));
    }
    std::map<std::string, std::uint64_t> epoch_anchors;
    const bool unchanged_accepted_epoch =
        cached_anchor && accepted_epoch && *discovered_epoch &&
        (**discovered_epoch).reference == *accepted_epoch;
    if (*discovered_epoch && !unchanged_accepted_epoch) {
        cached_anchor = nullptr;
        for (const auto& anchor : (**discovered_epoch).value.anchors) {
            epoch_anchors.emplace(anchor.commit_id, anchor.height);
        }
    }

    const auto heads_trace = platform::perf_trace::begin();
    std::map<std::string, std::vector<HeadReference>> marker_candidates;
    std::size_t sequence = 0;
    for (const auto& [commit_id, references] : inventory->marker_variants) {
        for (const auto& reference : references) {
            const auto marker_id = marker_object(reference);
            auto state =
                std::ranges::find(trusted_marker_identifiers, marker_id) !=
                        trusted_marker_identifiers.end()
                    ? std::expected<MarkerState, Error>{MarkerState::Valid}
                    : inspect_marker(
                          storage, reference, (*temporary)->root, sequence);
            if (!state) {
                return std::unexpected(state.error());
            }
            if (*state == MarkerState::Valid) {
                marker_candidates[commit_id].push_back(reference);
            }
        }
        if (marker_candidates[commit_id].empty()) {
            return std::unexpected(
                error(ErrorCode::InvalidMarker,
                      "all markers for a commit are invalid"));
        }
        sort_unique(marker_candidates[commit_id]);
    }

    if (marker_candidates.empty()) {
        platform::perf_trace::finish("head loading", heads_trace);
        if (*discovered_epoch) {
            return std::unexpected(
                error(ErrorCode::InconsistentInventory,
                      "Epoch exists without a valid history head"));
        }
        return LoadedHistory{};
    }
    platform::perf_trace::finish("head loading", heads_trace);

    const auto commits_trace = platform::perf_trace::begin();
    std::map<std::string, history::LoadedCommit> loaded;
    std::vector<HeadReference> authenticated_commit_variants;
    std::vector<std::pair<std::string, std::size_t>> pending;
    bool scoped_anchor_referenced =
        scoped && cached_anchor &&
        marker_candidates.contains(cached_anchor->commit_id);
    for (const auto& [commit_id, unused] : marker_candidates) {
        static_cast<void>(unused);
        pending.emplace_back(commit_id, 0);
    }

    while (!pending.empty()) {
        auto [commit_id, depth] = std::move(pending.back());
        pending.pop_back();
        if (depth > history::maximum_graph_depth) {
            return std::unexpected(
                error(ErrorCode::LimitExceeded, "history graph is too deep"));
        }
        if (loaded.contains(commit_id)) {
            continue;
        }
        if (cached_anchor && commit_id == cached_anchor->commit_id) {
            continue;
        }
        if (loaded.size() >= history::maximum_loaded_commit_count) {
            return std::unexpected(error(ErrorCode::LimitExceeded,
                                         "history contains too many commits"));
        }

        const auto marker_found = marker_candidates.find(commit_id);
        if (scoped && marker_found == marker_candidates.end()) {
            auto discovered =
                discover_scoped_commit_variants(storage, commit_id, *inventory);
            if (!discovered) {
                return std::unexpected(discovered.error());
            }
        }

        auto variants_for_attempt = [&]() {
            std::vector<HeadReference> variants;
            if (const auto found = inventory->commit_variants.find(commit_id);
                found != inventory->commit_variants.end()) {
                variants = found->second;
            }
            if (const auto found = marker_candidates.find(commit_id);
                found != marker_candidates.end()) {
                variants.insert(
                    variants.end(), found->second.begin(), found->second.end());
            }
            sort_unique(variants);
            return variants;
        };

        HeadReference authenticated_reference;
        auto commit = try_load_variants(storage,
                                        key,
                                        variants_for_attempt(),
                                        (*temporary)->root,
                                        sequence,
                                        &authenticated_reference);
        if (!commit && scoped && marker_found != marker_candidates.end() &&
            (commit.error().code == ErrorCode::MissingCommit ||
             commit.error().code == ErrorCode::InvalidCiphertext ||
             commit.error().code == ErrorCode::InvalidCommit)) {
            auto discovered =
                discover_scoped_commit_variants(storage, commit_id, *inventory);
            if (!discovered) {
                return std::unexpected(discovered.error());
            }
            commit = try_load_variants(storage,
                                       key,
                                       variants_for_attempt(),
                                       (*temporary)->root,
                                       sequence,
                                       &authenticated_reference);
        }
        if (!commit) {
            return std::unexpected(commit.error());
        }
        if (depth == 0 && commit->commit.height ==
                              std::numeric_limits<std::uint64_t>::max()) {
            return std::unexpected(error(ErrorCode::LimitExceeded,
                                         "head height cannot have a child"));
        }
        const auto parents = commit->commit.parents;
        if (const auto boundary = epoch_anchors.find(commit_id);
            boundary != epoch_anchors.end()) {
            if (commit->commit.height != boundary->second) {
                return std::unexpected(
                    error(ErrorCode::InvalidCommit,
                          "Epoch anchor height does not match its commit"));
            }
            commit->commit.parents.clear();
        }
        loaded.emplace(commit_id, std::move(*commit));
        authenticated_commit_variants.push_back(
            std::move(authenticated_reference));
        if (epoch_anchors.contains(commit_id)) {
            continue;
        }
        for (const auto& parent : parents) {
            if (scoped && cached_anchor && parent == cached_anchor->commit_id) {
                scoped_anchor_referenced = true;
            }
            pending.emplace_back(parent, depth + 1);
        }
    }

    if (!epoch_anchors.empty()) {
        for (const auto& [anchor_id, unused] : epoch_anchors) {
            static_cast<void>(unused);
            if (!loaded.contains(anchor_id)) {
                return std::unexpected(
                    error(ErrorCode::InvalidCommit,
                          "Epoch anchor is not reachable from a history head"));
            }
        }
    } else if (cached_anchor && scoped) {
        if (!scoped_anchor_referenced) {
            // Without proven linkage, retries loading without trusting the
            // anchor.
            return load_impl(storage,
                             key,
                             workspace_root,
                             std::nullopt,
                             nullptr,
                             true,
                             trusted_marker_identifiers);
        }
        loaded.emplace(
            cached_anchor->commit_id,
            history::LoadedCommit{
                .id = cached_anchor->commit_id,
                .commit = history::Commit{.height = cached_anchor->height,
                                          .parents = {},
                                          .tree = cached_anchor->tree}});
    } else if (cached_anchor) {
        const auto physical_anchor =
            inventory->commit_variants.find(cached_anchor->commit_id);
        const auto anchor_markers =
            marker_candidates.find(cached_anchor->commit_id);
        bool anchored = physical_anchor != inventory->commit_variants.end() &&
                        !physical_anchor->second.empty();
        if (anchored && anchor_markers != marker_candidates.end()) {
            anchored = std::ranges::any_of(
                anchor_markers->second, [&](const auto& reference) {
                    return std::ranges::find(physical_anchor->second,
                                             reference) !=
                           physical_anchor->second.end();
                });
        }
        std::set<std::string> descendants{cached_anchor->commit_id};
        while (anchored && descendants.size() <= loaded.size()) {
            const auto previous_size = descendants.size();
            for (const auto& [commit_id, commit] : loaded) {
                if (!commit.commit.parents.empty() &&
                    std::ranges::all_of(commit.commit.parents,
                                        [&](const auto& parent) {
                                            return descendants.contains(parent);
                                        })) {
                    descendants.insert(commit_id);
                }
            }
            if (descendants.size() == previous_size) {
                break;
            }
        }
        anchored = anchored && descendants.size() == loaded.size() + 1;
        if (!anchored) {
            return load_impl(
                storage, key, workspace_root, identifiers, nullptr, scoped);
        }
        loaded.emplace(
            cached_anchor->commit_id,
            history::LoadedCommit{
                .id = cached_anchor->commit_id,
                .commit = history::Commit{.height = cached_anchor->height,
                                          .parents = {},
                                          .tree = cached_anchor->tree}});
    }

    LoadedHistory result;
    result.authenticated_commit_variants =
        std::move(authenticated_commit_variants);
    result.marked_heads.reserve(marker_candidates.size());
    for (const auto& [commit_id, unused] : marker_candidates) {
        static_cast<void>(unused);
        result.marked_heads.push_back(commit_id);
        for (const auto& reference : marker_candidates.at(commit_id)) {
            result.marked_head_identifiers.push_back(marker_object(reference));
        }
    }
    std::ranges::sort(result.marked_head_identifiers);
    result.marked_head_identifiers.erase(
        std::ranges::unique(result.marked_head_identifiers).begin(),
        result.marked_head_identifiers.end());
    result.commits.reserve(loaded.size());
    for (auto& [unused, commit] : loaded) {
        static_cast<void>(unused);
        result.commits.push_back(std::move(commit));
    }
    if (!epoch_anchors.empty()) {
        for (const auto& [anchor_id, unused] : epoch_anchors) {
            static_cast<void>(unused);
            result.trusted_anchor_ids.push_back(anchor_id);
        }
    } else if (cached_anchor) {
        result.trusted_anchor_ids.push_back(cached_anchor->commit_id);
    }
    if (*discovered_epoch) {
        result.epoch = **discovered_epoch;
    }
    platform::perf_trace::finish("commit loading", commits_trace);
    return result;
}

} // namespace kasumi::application::history_storage::detail
