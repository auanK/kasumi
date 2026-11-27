#include "application/history_storage/commit_cache.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/cancellation.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <future>
#include <limits>
#include <system_error>
#include <thread>
#include <utility>

namespace kasumi::application::history_storage::detail {

std::expected<std::vector<std::uint8_t>, Error>
read_file(const std::filesystem::path& path, std::size_t maximum_size) {
    std::vector<std::uint8_t> bytes;
    std::array<std::uint8_t, 65536> scratch{};
    bool oversized = false;
    const auto streamed = platform::private_storage::stream_regular_file(
        path, scratch, [&](std::span<const std::uint8_t> chunk) {
            if (chunk.size() >
                maximum_size - std::min(maximum_size, bytes.size())) {
                oversized = true;
                return false;
            }
            bytes.insert(bytes.end(), chunk.begin(), chunk.end());
            return true;
        });
    if (oversized ||
        (!streamed &&
         streamed.error().kind ==
             platform::private_storage::StreamErrorKind::SizeMismatch)) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "temporary file exceeds limit"));
    }
    if (!streamed) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, streamed.error().detail));
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
    if (workspace != nullptr && !workspace->workspace.root.empty()) {
        platform::cleanup_workspace(workspace->workspace);
    }
    delete workspace;
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
        auto created = platform::create_workspace_at(candidate);
        if (created) {
            return TemporaryWorkspace{new TemporaryWorkspaceData{*created},
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
                          const RemoteLayout& layout,
                          const HeadReference& reference,
                          const std::filesystem::path& destination) {
    remove_file(destination);
    auto result =
        transport::get(storage, commit_object(layout, reference), destination);
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
               const RemoteLayout& layout,
               const HeadReference& reference,
               const std::filesystem::path& workspace,
               std::size_t& sequence) {
    const auto path =
        workspace / ("marker-inspect-" + std::to_string(sequence++));
    remove_file(path);
    auto fetched =
        transport::get(storage, marker_object(layout, reference), path);
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
    if (decoded && *decoded == reference) {
        return MarkerState::Valid;
    }
    return MarkerState::Invalid;
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

std::expected<std::uintmax_t, Error>
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
    return size;
}

struct LocalAuthResult {
    enum class Status { Ok, InvalidCiphertext, InvalidCommit, IoError };
    Status status = Status::InvalidCiphertext;
    std::optional<history::LoadedCommit> commit;
    std::optional<Error> io_error;
};

LocalAuthResult authenticate_local_ciphertext(
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const HeadReference& reference,
    const std::filesystem::path& ciphertext,
    const std::filesystem::path& plaintext) {
    auto cipher_size = validate_ciphertext_size(ciphertext);
    if (!cipher_size) {
        if (cipher_size.error().code == ErrorCode::LimitExceeded) {
            return {.status = LocalAuthResult::Status::InvalidCiphertext};
        }
        return {.status = LocalAuthResult::Status::IoError,
                .io_error = cipher_size.error()};
    }
    auto matches = ciphertext_matches(ciphertext, reference.ciphertext_id);
    if (!matches) {
        return {.status = LocalAuthResult::Status::IoError,
                .io_error = matches.error()};
    }
    if (!*matches ||
        !crypto::decrypt_file(
            ciphertext, plaintext, key, crypto::FilePurpose::History)) {
        return {.status = LocalAuthResult::Status::InvalidCiphertext};
    }

    auto bytes = read_file(plaintext, history::maximum_commit_plaintext_size);
    if (!bytes) {
        if (bytes.error().code == ErrorCode::LimitExceeded) {
            return {.status = LocalAuthResult::Status::InvalidCommit};
        }
        return {.status = LocalAuthResult::Status::IoError,
                .io_error = bytes.error()};
    }
    auto commit = history::deserialize(*bytes);
    if (!commit) {
        return {.status = LocalAuthResult::Status::InvalidCommit};
    }
    auto canonical = history::serialize(*commit);
    if (!canonical) {
        return {.status = LocalAuthResult::Status::InvalidCommit};
    }
    const bool valid_commit =
        crypto::commit_identifier(key, *canonical) == reference.commit_id &&
        *canonical == *bytes;
    if (!valid_commit) {
        return {.status = LocalAuthResult::Status::InvalidCommit};
    }
    return {
        .status = LocalAuthResult::Status::Ok,
        .commit = history::LoadedCommit{.id = reference.commit_id,
                                        .commit = std::move(*commit)},
    };
}

std::optional<history::LoadedCommit> try_load_local_variant_only(
    const RemoteLayout& layout,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const HeadReference& reference,
    const std::filesystem::path& workspace,
    std::size_t sequence,
    CommitCache* commit_cache) {
    auto ciphertext =
        workspace / (reference.commit_id + "_" + reference.ciphertext_id);
    std::error_code prefetched_error;
    const bool prefetched =
        std::filesystem::is_regular_file(ciphertext, prefetched_error);
    bool from_disk_cache = false;
    if (!prefetched) {
        if (commit_cache == nullptr) {
            return std::nullopt;
        }
        auto cached_path = lookup_cached_ciphertext_path(
            *commit_cache, layout.commits_prefix, reference);
        if (!cached_path) {
            return std::nullopt;
        }
        ciphertext = std::move(*cached_path);
        from_disk_cache = true;
    }

    const auto plaintext =
        workspace / ("predecode-plain-" + std::to_string(sequence));
    auto auth = authenticate_local_ciphertext(key, reference, ciphertext, plaintext);
    remove_file(plaintext);
    if (auth.status != LocalAuthResult::Status::Ok || !auth.commit.has_value()) {
        // Leave ciphertext intact so sequential fallback performs exact error
        // classification or corrupt disk-cache self-healing.
        return std::nullopt;
    }
    if (commit_cache != nullptr) {
        store_cached_commit(*commit_cache,
                            layout.commits_prefix,
                            reference,
                            *auth.commit,
                            from_disk_cache ? nullptr : &ciphertext);
    }
    if (!from_disk_cache) {
        remove_file(ciphertext);
    }
    return std::move(*auth.commit);
}

VariantResult
try_load_variant(transport::Transport& storage,
                 const RemoteLayout& layout,
                 std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                 const HeadReference& reference,
                 const std::filesystem::path& workspace,
                 std::size_t sequence,
                 CommitCache* commit_cache,
                 bool allow_cache_read) {
    if (commit_cache != nullptr && allow_cache_read) {
        if (auto cached = lookup_cached_commit(
                *commit_cache, layout.commits_prefix, reference)) {
            return LoadedVariant{
                .state = VariantState::Valid,
                .commit = std::move(*cached),
            };
        }
    }

    auto ciphertext =
        workspace / (reference.commit_id + "_" + reference.ciphertext_id);
    std::error_code prefetched_error;
    bool prefetched =
        std::filesystem::is_regular_file(ciphertext, prefetched_error);
    bool from_disk_cache = false;
    if (!prefetched && commit_cache != nullptr && allow_cache_read) {
        if (auto cached_path = lookup_cached_ciphertext_path(
                *commit_cache, layout.commits_prefix, reference)) {
            ciphertext = std::move(*cached_path);
            from_disk_cache = true;
        }
    }
    if (!prefetched && !from_disk_cache) {
        ciphertext = workspace / ("ciphertext-" + std::to_string(sequence));
    }
    const auto plaintext =
        workspace / ("plaintext-" + std::to_string(sequence));
    const auto cleanup = [&] {
        if (!from_disk_cache) {
            remove_file(ciphertext);
        }
        remove_file(plaintext);
    };
    const auto finish_invalid = [&](VariantState state) -> VariantResult {
        cleanup();
        return LoadedVariant{.state = state, .commit = std::nullopt};
    };

    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto reset_from_corrupt_disk_cache = [&] {
            evict_cached_ciphertext(
                *commit_cache, layout.commits_prefix, reference);
            remove_file(plaintext);
            from_disk_cache = false;
            prefetched = false;
            ciphertext = workspace / ("ciphertext-" + std::to_string(sequence));
        };

        if (!prefetched && !from_disk_cache) {
            auto downloaded =
                download_commit_candidate(storage, layout, reference, ciphertext);
            if (!downloaded) {
                cleanup();
                if (downloaded.error().code == ErrorCode::MissingCommit) {
                    return LoadedVariant{.state = VariantState::Missing,
                                         .commit = std::nullopt};
                }
                return std::unexpected(downloaded.error());
            }
        }
        auto auth =
            authenticate_local_ciphertext(key, reference, ciphertext, plaintext);
        if (auth.status != LocalAuthResult::Status::Ok) {
            if (from_disk_cache && attempt == 0) {
                reset_from_corrupt_disk_cache();
                continue;
            }
            if (auth.status == LocalAuthResult::Status::InvalidCiphertext) {
                return finish_invalid(VariantState::InvalidCiphertext);
            }
            if (auth.status == LocalAuthResult::Status::InvalidCommit) {
                return finish_invalid(VariantState::InvalidCommit);
            }
            cleanup();
            return std::unexpected(std::move(*auth.io_error));
        }
        history::LoadedCommit loaded_commit = std::move(*auth.commit);
        if (commit_cache != nullptr) {
            store_cached_commit(*commit_cache,
                                layout.commits_prefix,
                                reference,
                                loaded_commit,
                                from_disk_cache ? nullptr : &ciphertext);
        }
        cleanup();
        return LoadedVariant{
            .state = VariantState::Valid,
            .commit = std::move(loaded_commit),
        };
    }

    cleanup();
    return LoadedVariant{.state = VariantState::InvalidCiphertext,
                         .commit = std::nullopt};
}

std::expected<history::LoadedCommit, Error>
try_load_variants(transport::Transport& storage,
                  const RemoteLayout& layout,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                  std::vector<HeadReference> references,
                  const std::filesystem::path& workspace,
                  std::size_t& sequence,
                  HeadReference* authenticated_reference,
                  CommitCache* commit_cache,
                  const ObjectMap* confirmed_physical_variants) {
    if (references.empty()) {
        return std::unexpected(
            error(ErrorCode::MissingCommit, "commit object is missing"));
    }
    bool saw_invalid_ciphertext = false;
    bool saw_invalid_commit = false;
    sort_unique(references);
    const std::vector<HeadReference>* confirmed_for_commit = nullptr;
    if (confirmed_physical_variants != nullptr) {
        if (const auto found =
                confirmed_physical_variants->find(references.front().commit_id);
            found != confirmed_physical_variants->end()) {
            confirmed_for_commit = &found->second;
        }
    }
    for (const auto& reference : references) {
        const bool allow_cache_read =
            confirmed_for_commit != nullptr &&
            std::ranges::binary_search(*confirmed_for_commit, reference);
        auto loaded = try_load_variant(storage,
                                       layout,
                                       key,
                                       reference,
                                       workspace,
                                       sequence++,
                                       commit_cache,
                                       allow_cache_read);
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
                        const RemoteLayout& layout,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const history::Commit& expected,
                        const HeadReference& reference,
                        const std::filesystem::path& workspace,
                        std::size_t& sequence) {
    auto loaded = try_load_variant(
        storage, layout, key, reference, workspace, sequence++);
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

std::expected<void, Error>
prefetch_commit_batch(transport::Transport& storage,
                      const RemoteLayout& layout,
                      const ObjectMap& commit_variants,
                      const std::filesystem::path& destination_root,
                      std::size_t min_objects,
                      CommitCache* commit_cache) {
    if (storage.storage.get_batch == nullptr) {
        return {};
    }
    transport::GetBatch batch{
        .source_prefix =
            std::string{trim_trailing_slash(layout.commits_prefix)},
        .destination_root = destination_root,
    };
    for (const auto& [unused, references] : commit_variants) {
        static_cast<void>(unused);
        for (const auto& reference : references) {
            if (commit_cache != nullptr &&
                has_cached_commit_or_ciphertext(
                    *commit_cache, layout.commits_prefix, reference)) {
                continue;
            }
            batch.identifiers.push_back(reference.commit_id + "_" +
                                        reference.ciphertext_id);
        }
    }
    if (batch.identifiers.size() < min_objects) {
        return {};
    }
    if (auto prefetched = transport::get_batch(storage, batch); !prefetched) {
        return std::unexpected(transport_error(prefetched.error()));
    }
    return {};
}

std::expected<bool, Error>
verify_remote_physical_hash(transport::Transport& storage,
                            std::string_view identifier,
                            std::string_view local_hash,
                            std::string_view mismatch_detail) {
    if (local_hash.empty()) {
        return false;
    }
    auto remote_hash = transport::physical_hash(storage, identifier, "sha256");
    if (!remote_hash) {
        if (remote_hash.error().code == transport::ErrorCode::Unsupported) {
            return false;
        }
        if (remote_hash.error().code == transport::ErrorCode::ObjectNotFound) {
            return std::unexpected(
                error(ErrorCode::VerificationFailure,
                      "remote object disappeared before verification"));
        }
        return std::unexpected(transport_error(remote_hash.error()));
    }
    if (*remote_hash != local_hash) {
        return std::unexpected(error(ErrorCode::VerificationFailure,
                                     std::string{mismatch_detail}));
    }
    return true;
}

std::expected<HistoryInventory, Error>
build_scoped_history_inventory(transport::Transport& storage,
                               const RemoteLayout& layout) {
    auto listing = list_identifiers(storage, layout.heads_prefix);
    if (!listing) {
        return std::unexpected(listing.error());
    }
    if (listing->empty()) {
        return HistoryInventory{};
    }

    HistoryInventory inventory;
    for (const auto& name : *listing) {
        const auto identifier = name.starts_with(layout.heads_prefix)
                                    ? name
                                    : layout.heads_prefix + name;
        if (is_control_object(layout, identifier)) {
            continue;
        }
        auto reference = parse_marker_object(layout, identifier);
        if (!reference) {
            continue;
        }
        inventory.identifiers.push_back(identifier);
        inventory.marker_variants[reference->commit_id].push_back(
            std::move(*reference));
    }
    sort_unique(inventory.identifiers);
    if (auto finalized = finalize_history_inventory(inventory); !finalized) {
        return std::unexpected(finalized.error());
    }
    return inventory;
}

std::expected<void, Error>
discover_scoped_commit_variants(transport::Transport& storage,
                                const RemoteLayout& layout,
                                std::string_view commit_id,
                                HistoryInventory& inventory) {
    if (!valid_hex_id(commit_id)) {
        return std::unexpected(
            error(ErrorCode::InvalidIdentifier, "invalid commit identifier"));
    }
    if (inventory.all_commits_listed) {
        return {};
    }
    const auto prefix = trim_trailing_slash(layout.commits_prefix);
    auto listing = list_identifiers(storage, prefix);
    if (!listing) {
        return std::unexpected(listing.error());
    }
    inventory.all_commits_listed = true;
    if (listing->empty()) {
        return {};
    }

    for (const auto& name : *listing) {
        const auto identifier = name.starts_with(layout.commits_prefix)
                                    ? name
                                    : layout.commits_prefix + name;
        auto reference = parse_commit_object(layout, identifier);
        if (!reference) {
            continue;
        }
        inventory.identifiers.push_back(identifier);
        inventory.commit_variants[reference->commit_id].push_back(
            std::move(*reference));
    }
    sort_unique(inventory.identifiers);
    if (inventory.identifiers.size() > maximum_history_object_count) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "history variant budget exceeded"));
    }
    for (auto& [unused, variants] : inventory.commit_variants) {
        static_cast<void>(unused);
        sort_unique(variants);
        if (variants.size() > maximum_ciphertext_variants_per_commit) {
            return std::unexpected(error(ErrorCode::LimitExceeded,
                                         "history variant budget exceeded"));
        }
    }
    return {};
}

LoadResult load_impl(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const std::filesystem::path& workspace_root,
                     std::optional<std::span<const std::string>> identifiers,
                     const KnownHistoryFrontier* frontier,
                     bool scoped,
                     std::span<const std::string> trusted_marker_identifiers,
                     CommitCache* commit_cache) {
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
    const auto layout = derive_remote_layout(key);

    auto cancelled = [&](bool check_cancellation) -> std::optional<Error> {
        if (check_cancellation && platform::cancellation::requested()) {
            return error(ErrorCode::TransportFailure,
                         "operation cancelled by user");
        }
        return std::nullopt;
    };

    auto load_latest_epoch = [&](std::optional<epoch::Reference> accepted_epoch,
                                 bool check_cancellation)
        -> std::expected<std::optional<epoch::VerifiedEpoch>, Error> {
        if (auto cancel = cancelled(check_cancellation)) {
            return std::unexpected(*cancel);
        }
        auto raw_epoch =
            identifiers ? epoch::load_latest(storage,
                                             key,
                                             workspace_root,
                                             *identifiers,
                                             accepted_epoch,
                                             commit_cache)
                        : epoch::load_latest(storage,
                                             key,
                                             workspace_root,
                                             accepted_epoch,
                                             commit_cache);
        if (auto cancel = cancelled(check_cancellation)) {
            return std::unexpected(*cancel);
        }
        if (!raw_epoch) {
            const auto code = [&] {
                switch (raw_epoch.error().code) {
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
            return std::unexpected(error(code, raw_epoch.error().detail));
        }
        return *raw_epoch;
    };

    const auto stop_token = platform::cancellation::current_stop_token();
    std::future<std::expected<std::optional<epoch::VerifiedEpoch>, Error>>
        scoped_epoch;
    // Native batch backends already support concurrent history reads.
    if (scoped && storage.storage.get_batch != nullptr) {
        scoped_epoch = std::async(std::launch::async, [&, stop_token] {
            const platform::cancellation::ScopedStopToken stop_scope{
                stop_token};
            return load_latest_epoch(
                frontier ? frontier->accepted_epoch : std::nullopt, true);
        });
    }
    auto inventory = [&]() {
        if (scoped) {
            return build_scoped_history_inventory(storage, layout);
        }
        return identifiers ? build_history_inventory(*identifiers, layout)
                           : build_history_inventory(storage, layout);
    }();
    if (!inventory) {
        return std::unexpected(inventory.error());
    }

    std::optional<epoch::VerifiedEpoch> discovered_epoch;
    std::map<std::string, std::vector<HeadReference>> marker_candidates;
    std::map<std::string, std::uint64_t> epoch_anchors;
    const KnownHistoryAnchor* cached_anchor = nullptr;

    auto load_markers = [&](const std::filesystem::path& workspace_dir,
                            bool check_cancellation)
        -> std::expected<std::map<std::string, std::vector<HeadReference>>,
                         Error> {
        std::map<std::string, std::vector<HeadReference>> candidates;
        std::size_t sequence = 0;
        for (const auto& [commit_id, references] : inventory->marker_variants) {
            if (auto cancel = cancelled(check_cancellation)) {
                return std::unexpected(*cancel);
            }
            std::vector<HeadReference> valid;
            for (const auto& reference : references) {
                const auto marker_id = marker_object(layout, reference);
                const bool trusted_or_cached =
                    std::ranges::find(trusted_marker_identifiers, marker_id) !=
                        trusted_marker_identifiers.end() ||
                    (commit_cache != nullptr &&
                     has_validated_marker(*commit_cache, marker_id));
                auto state =
                    trusted_or_cached
                        ? std::expected<MarkerState, Error>{MarkerState::Valid}
                        : inspect_marker(storage,
                                         layout,
                                         reference,
                                         workspace_dir,
                                         sequence);
                if (!state) {
                    return std::unexpected(state.error());
                }
                if (*state == MarkerState::Valid) {
                    if (!trusted_or_cached && commit_cache != nullptr) {
                        record_validated_marker(*commit_cache, marker_id);
                    }
                    valid.push_back(reference);
                }
            }
            if (valid.empty()) {
                return std::unexpected(
                    error(ErrorCode::InvalidMarker,
                          "all markers for a commit are invalid"));
            }
            sort_unique(valid);
            candidates.emplace(commit_id, std::move(valid));
        }
        return candidates;
    };

    std::map<HeadReference, history::LoadedCommit> predecoded_commits;
    if (native_complete_batch) {
        auto marker_temporary = make_workspace(temporary_root);
        if (!marker_temporary) {
            return std::unexpected(marker_temporary.error());
        }

        struct RemoteHistoryReads {
            std::expected<void, Error> commit_batch_result;
            std::expected<std::optional<epoch::VerifiedEpoch>, Error>
                epoch_result;
            std::expected<std::map<std::string, std::vector<HeadReference>>,
                          Error>
                marker_result;
            std::map<HeadReference, history::LoadedCommit> predecoded_commits;
        } reads;

        auto fetch_commit_batch = [&]() -> std::expected<void, Error> {
            if (auto cancel = cancelled(true)) {
                return std::unexpected(*cancel);
            }
            if (auto prefetched = prefetch_commit_batch(
                    storage,
                    layout,
                    inventory->commit_variants,
                    (*temporary)->workspace.root,
                    1,
                    commit_cache);
                !prefetched) {
                return prefetched;
            }
            if (auto cancel = cancelled(true)) {
                return std::unexpected(*cancel);
            }

            std::vector<HeadReference> to_decode;
            to_decode.reserve(inventory->commit_variants.size());
            for (const auto& [unused, references] :
                 inventory->commit_variants) {
                static_cast<void>(unused);
                for (const auto& reference : references) {
                    if (commit_cache != nullptr) {
                        if (auto cached = lookup_cached_commit(
                                *commit_cache, layout.commits_prefix, reference)) {
                            reads.predecoded_commits.emplace(
                                reference, std::move(*cached));
                            continue;
                        }
                    }
                    to_decode.push_back(reference);
                }
            }

            if (to_decode.size() >= 2U) {
                const auto hardware_threads = static_cast<std::size_t>(
                    std::thread::hardware_concurrency());
                const std::size_t worker_count = std::min<std::size_t>(
                    {to_decode.size(),
                     std::max<std::size_t>(1U, hardware_threads),
                     8U});
                std::atomic<std::size_t> next_index{0};
                std::vector<std::optional<history::LoadedCommit>> decoded(
                    to_decode.size());
                {
                    std::vector<std::jthread> decode_workers;
                    decode_workers.reserve(worker_count);
                    for (std::size_t w = 0; w < worker_count; ++w) {
                        decode_workers.emplace_back([&, stop_token] {
                            const platform::cancellation::ScopedStopToken
                                stop_scope{stop_token};
                            for (;;) {
                                if (platform::cancellation::requested()) {
                                    break;
                                }
                                const auto idx = next_index.fetch_add(
                                    1U, std::memory_order_relaxed);
                                if (idx >= to_decode.size()) {
                                    break;
                                }
                                decoded[idx] = try_load_local_variant_only(
                                    layout,
                                    key,
                                    to_decode[idx],
                                    (*temporary)->workspace.root,
                                    idx,
                                    commit_cache);
                            }
                        });
                    }
                }
                for (std::size_t idx = 0; idx < to_decode.size(); ++idx) {
                    if (decoded[idx].has_value()) {
                        reads.predecoded_commits.emplace(
                            to_decode[idx], std::move(*decoded[idx]));
                    }
                }
            }
            return {};
        };

        {
            std::jthread batch_thread([&, stop_token] {
                const platform::cancellation::ScopedStopToken stop_scope{
                    stop_token};
                reads.commit_batch_result = fetch_commit_batch();
            });
            std::jthread epoch_thread([&, stop_token] {
                const platform::cancellation::ScopedStopToken stop_scope{
                    stop_token};
                reads.epoch_result = load_latest_epoch(std::nullopt, true);
            });
            std::jthread marker_thread([&, stop_token] {
                const platform::cancellation::ScopedStopToken stop_scope{
                    stop_token};
                reads.marker_result =
                    load_markers((*marker_temporary)->workspace.root, true);
            });
        }

        // Deterministic error reduction precedence: commit batch, then epoch,
        // then marker.
        if (!reads.commit_batch_result) {
            return std::unexpected(reads.commit_batch_result.error());
        }
        if (!reads.epoch_result) {
            return std::unexpected(reads.epoch_result.error());
        }
        if (!reads.marker_result) {
            return std::unexpected(reads.marker_result.error());
        }
        if (auto cancel = cancelled(true)) {
            return std::unexpected(*cancel);
        }

        discovered_epoch = std::move(*reads.epoch_result);
        marker_candidates = std::move(*reads.marker_result);
        predecoded_commits = std::move(reads.predecoded_commits);

        if (discovered_epoch) {
            for (const auto& anchor : discovered_epoch->value.anchors) {
                epoch_anchors.emplace(anchor.commit_id, anchor.height);
            }
        }
    } else {
        if (frontier && frontier->anchors.size() > 1) {
            return std::unexpected(error(
                ErrorCode::InvalidInput,
                "local history frontier contains unsupported cached anchors"));
        }
        if (frontier && !frontier->anchors.empty()) {
            cached_anchor = &frontier->anchors.front();
        }
        if (cached_anchor &&
            (!valid_hex_id(cached_anchor->commit_id) ||
             !valid_snapshot(cached_anchor->tree, false) ||
             !history::valid_storage_manifest(cached_anchor->storage,
                                              cached_anchor->tree))) {
            return std::unexpected(
                error(ErrorCode::InvalidInput, "invalid history anchor"));
        }

        const auto accepted_epoch = frontier
                                        ? frontier->accepted_epoch
                                        : std::optional<epoch::Reference>{};
        auto raw_epoch = scoped_epoch.valid()
                             ? scoped_epoch.get()
                             : load_latest_epoch(accepted_epoch, false);
        if (!raw_epoch) {
            return std::unexpected(raw_epoch.error());
        }
        if (auto cancel = cancelled(scoped)) {
            return std::unexpected(*cancel);
        }
        discovered_epoch = *raw_epoch;
        const bool unchanged_accepted_epoch =
            cached_anchor && accepted_epoch && discovered_epoch &&
            discovered_epoch->reference == *accepted_epoch;
        if (discovered_epoch && !unchanged_accepted_epoch) {
            cached_anchor = nullptr;
            for (const auto& anchor : discovered_epoch->value.anchors) {
                epoch_anchors.emplace(anchor.commit_id, anchor.height);
            }
        }

        auto loaded_markers = load_markers((*temporary)->workspace.root, false);
        if (!loaded_markers) {
            return std::unexpected(loaded_markers.error());
        }
        marker_candidates = std::move(*loaded_markers);
    }

    if (marker_candidates.empty()) {
        if (discovered_epoch) {
            return std::unexpected(
                error(ErrorCode::InconsistentInventory,
                      "Epoch exists without a valid history head"));
        }
        return LoadedHistory{};
    }

    std::map<std::string, std::size_t> read_positions;
    std::set<std::string> prefetch_attempted;
    // Previous addresses shorten discovery, never the authenticated graph.
    if (scoped && frontier &&
        (discovered_epoch ? std::optional{discovered_epoch->reference}
                          : std::nullopt) == frontier->observed_epoch) {
        std::vector<std::string> markers;
        for (const auto& [id, references] : marker_candidates) {
            static_cast<void>(id);
            for (const auto& reference : references) {
                markers.push_back(marker_object(layout, reference));
            }
        }
        sort_unique(markers);
        if (markers == frontier->observed_markers) {
            if (frontier->observed_variants.size() >
                history::maximum_loaded_commit_count) {
                return std::unexpected(error(ErrorCode::LimitExceeded,
                                             "too many observed variants"));
            }
            for (std::size_t i = 0; i < frontier->observed_variants.size();
                 ++i) {
                const auto& reference = frontier->observed_variants[i];
                if (!valid(reference) ||
                    !read_positions.emplace(reference.commit_id, i).second) {
                    return std::unexpected(error(ErrorCode::InvalidInput,
                                                 "invalid observed variant"));
                }
                inventory->commit_variants[reference.commit_id] = {reference};
            }
        }
    }

    std::map<std::string, history::LoadedCommit> loaded;
    std::vector<HeadReference> authenticated_commit_variants;
    std::vector<std::pair<std::string, std::size_t>> pending;
    bool scoped_anchor_referenced =
        scoped && cached_anchor &&
        marker_candidates.contains(cached_anchor->commit_id);
    for (const auto& entry : marker_candidates) {
        pending.emplace_back(entry.first, 0);
    }

    std::size_t commit_sequence = 0;
    while (!pending.empty()) {
        auto [commit_id, depth] = std::move(pending.back());
        pending.pop_back();
        if (depth > history::maximum_graph_depth) {
            return std::unexpected(
                error(ErrorCode::LimitExceeded, "history graph is too deep"));
        }
        if (loaded.contains(commit_id) ||
            (cached_anchor && commit_id == cached_anchor->commit_id)) {
            continue;
        }
        if (loaded.size() >= history::maximum_loaded_commit_count) {
            return std::unexpected(error(ErrorCode::LimitExceeded,
                                         "history contains too many commits"));
        }

        if (auto position = read_positions.find(commit_id);
            position != read_positions.end() &&
            !prefetch_attempted.contains(commit_id)) {
            ObjectMap window;
            for (std::size_t i = position->second;
                 i < frontier->observed_variants.size() && window.size() < 8;
                 ++i) {
                const auto& reference = frontier->observed_variants[i];
                if (!loaded.contains(reference.commit_id) &&
                    (!cached_anchor ||
                     reference.commit_id != cached_anchor->commit_id) &&
                    prefetch_attempted.insert(reference.commit_id).second) {
                    window[reference.commit_id].push_back(reference);
                }
            }
            auto fetched = prefetch_commit_batch(
                storage,
                layout,
                window,
                (*temporary)->workspace.root,
                2,
                inventory->all_commits_listed ? commit_cache : nullptr);
            if (!fetched) {
                // Classify stale/missing variants through the normal loader.
                for (const auto& [id, references] : window) {
                    for (const auto& reference : references) {
                        remove_file((*temporary)->workspace.root /
                                    (id + "_" + reference.ciphertext_id));
                    }
                }
            }
            if (auto cancel = cancelled(true)) {
                return std::unexpected(*cancel);
            }
        }

        const auto marker_found = marker_candidates.find(commit_id);
        if (scoped && marker_found == marker_candidates.end() &&
            !inventory->commit_variants.contains(commit_id)) {
            auto discovered = discover_scoped_commit_variants(
                storage, layout, commit_id, *inventory);
            if (!discovered) {
                return std::unexpected(discovered.error());
            }
        }

        HeadReference authenticated_reference;
        auto attempt_load = [&]() -> std::expected<history::LoadedCommit, Error> {
            std::vector<HeadReference> variants;
            if (const auto found = inventory->commit_variants.find(commit_id);
                found != inventory->commit_variants.end()) {
                variants = found->second;
            }
            if (marker_found != marker_candidates.end()) {
                variants.insert(variants.end(),
                                marker_found->second.begin(),
                                marker_found->second.end());
            }
            sort_unique(variants);
            if (!predecoded_commits.empty()) {
                for (const auto& variant : variants) {
                    if (const auto predecoded =
                            predecoded_commits.find(variant);
                        predecoded != predecoded_commits.end()) {
                        authenticated_reference = variant;
                        auto extracted = std::move(predecoded->second);
                        predecoded_commits.erase(predecoded);
                        return extracted;
                    }
                }
            }
            return try_load_variants(
                storage,
                layout,
                key,
                variants,
                (*temporary)->workspace.root,
                commit_sequence,
                &authenticated_reference,
                commit_cache,
                inventory->all_commits_listed ? &inventory->commit_variants
                                              : nullptr);
        };

        auto commit = attempt_load();
        if (!commit && scoped &&
            (commit.error().code == ErrorCode::MissingCommit ||
             commit.error().code == ErrorCode::InvalidCiphertext ||
             commit.error().code == ErrorCode::InvalidCommit)) {
            if (auto discovered = discover_scoped_commit_variants(
                    storage, layout, commit_id, *inventory);
                !discovered) {
                return std::unexpected(discovered.error());
            }
            commit = attempt_load();
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
        const bool is_anchor = epoch_anchors.contains(commit_id);
        if (is_anchor) {
            if (commit->commit.height != epoch_anchors.at(commit_id)) {
                return std::unexpected(
                    error(ErrorCode::InvalidCommit,
                          "Epoch anchor height does not match its commit"));
            }
            commit->commit.parents.clear();
        }
        loaded.emplace(commit_id, std::move(*commit));
        authenticated_commit_variants.push_back(
            std::move(authenticated_reference));
        if (is_anchor) {
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
        for (const auto& entry : epoch_anchors) {
            if (!loaded.contains(entry.first)) {
                return std::unexpected(
                    error(ErrorCode::InvalidCommit,
                          "Epoch anchor is not reachable from a history head"));
            }
        }
    } else if (cached_anchor) {
        bool anchored = scoped_anchor_referenced;
        if (!scoped) {
            const auto physical_anchor =
                inventory->commit_variants.find(cached_anchor->commit_id);
            const auto anchor_markers =
                marker_candidates.find(cached_anchor->commit_id);
            anchored = physical_anchor != inventory->commit_variants.end() &&
                       !physical_anchor->second.empty();
            if (anchored && anchor_markers != marker_candidates.end()) {
                anchored = std::ranges::any_of(
                    anchor_markers->second, [&](const auto& reference) {
                        return std::ranges::find(physical_anchor->second,
                                                 reference) !=
                               physical_anchor->second.end();
                    });
            }
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
        if (!anchored || descendants.size() != loaded.size() + 1) {
            // Without proven linkage, retries loading without trusting the
            // anchor.
            return load_impl(storage,
                             key,
                             workspace_root,
                             scoped ? std::nullopt : identifiers,
                             nullptr,
                             scoped,
                             trusted_marker_identifiers,
                             commit_cache);
        }
        loaded.emplace(
            cached_anchor->commit_id,
            history::LoadedCommit{
                .id = cached_anchor->commit_id,
                .commit = history::Commit{.height = cached_anchor->height,
                                          .parents = {},
                                          .tree = cached_anchor->tree,
                                          .storage = cached_anchor->storage}});
    }

    LoadedHistory result;
    result.authenticated_commit_variants =
        std::move(authenticated_commit_variants);
    result.marked_heads.reserve(marker_candidates.size());
    for (const auto& [commit_id, references] : marker_candidates) {
        result.marked_heads.push_back(commit_id);
        for (const auto& reference : references) {
            result.marked_head_identifiers.push_back(
                marker_object(layout, reference));
        }
    }
    sort_unique(result.marked_head_identifiers);
    result.commits.reserve(loaded.size());
    for (auto& entry : loaded) {
        result.commits.push_back(std::move(entry.second));
    }
    if (!epoch_anchors.empty()) {
        for (const auto& entry : epoch_anchors) {
            result.trusted_anchor_ids.push_back(entry.first);
        }
    } else if (cached_anchor) {
        result.trusted_anchor_ids.push_back(cached_anchor->commit_id);
    }
    if (discovered_epoch) {
        result.epoch = *discovered_epoch;
    }
    if (commit_cache != nullptr && inventory->all_commits_listed) {
        prune_unlisted_memory_commits(
            *commit_cache, layout.commits_prefix, inventory->commit_variants);
    }
    return result;
}

} // namespace kasumi::application::history_storage::detail
