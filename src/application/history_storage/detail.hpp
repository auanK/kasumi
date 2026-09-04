#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_DETAIL_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_DETAIL_HPP

#include "application/history_storage/history_storage.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::history_storage::detail {

// Format and defensive limits for remote history.
inline constexpr std::string_view commit_prefix = "history/commits/";
inline constexpr std::string_view heads_prefix = "history/heads/";
inline constexpr std::string_view commit_suffix = ".kcom";
inline constexpr std::string_view head_suffix = ".head";
inline constexpr std::size_t marker_size = 69;
inline constexpr std::size_t maximum_history_object_count = 8192;
inline constexpr std::size_t maximum_ciphertext_variants_per_commit = 64;
inline constexpr std::uint64_t maximum_ciphertext_chunk_count =
    (history::maximum_commit_plaintext_size + crypto::CHUNK_SIZE - 1) /
    crypto::CHUNK_SIZE;
inline constexpr std::uintmax_t maximum_commit_ciphertext_size =
    static_cast<std::uintmax_t>(history::maximum_commit_plaintext_size) +
    crypto::FILE_HEADER_SIZE +
    maximum_ciphertext_chunk_count * crypto::MAC_SIZE;

// Variants grouped by commit identifier.
using ObjectMap = std::map<std::string, std::vector<HeadReference>>;

// History objects classified by commit.
struct HistoryInventory {
    // Identifiers found under history/.
    std::set<std::string> identifiers;
    ObjectMap commit_variants;
    ObjectMap marker_variants;
};

// Objects added by a publication.
struct PublicationDelta {
    bool adds_commit_object = false;
    bool adds_marker_object = false;
    bool adds_marked_commit = false;
};

// Creates a local failure.
Error error(ErrorCode code, std::string detail);
// Converts a transport failure.
Error transport_error(const transport::Error& source);
// Converts a history core failure.
Error history_error(const history::Error& source);

// Validates a canonical hexadecimal identifier.
bool valid_hex_id(std::string_view id) noexcept;
// Builds the remote identifier for a commit variant.
std::string commit_object(const HeadReference& reference);
// Extracts a reference from a commit identifier.
std::optional<HeadReference> parse_commit_object(std::string_view identifier);
// Sorts and removes duplicate references.
void sort_unique(std::vector<HeadReference>& references);

// Builds an inventory of all remote history objects.
std::expected<HistoryInventory, Error>
build_history_inventory(transport::Transport& storage);
// Classifies an already observed remote listing.
std::expected<HistoryInventory, Error>
build_history_inventory(std::span<const std::string> identifiers);

// Computes new objects required by the publication.
PublicationDelta publication_delta(const HistoryInventory& inventory,
                                   const HeadReference& reference);

// Rejects publications exceeding defensive limits.
std::expected<void, Error>
validate_publication_budget(const HistoryInventory& inventory,
                            const HeadReference& reference,
                            const PublicationDelta& delta,
                            bool check_global_count = true);

// Reads a temporary file respecting the specified limit.
std::expected<std::vector<std::uint8_t>, Error>
read_file(const std::filesystem::path& path, std::size_t maximum_size);
// Writes bytes to a temporary file.
std::expected<void, Error> write_file(const std::filesystem::path& path,
                                      std::span<const std::uint8_t> bytes);
// Attempts to remove a temporary file.
void remove_file(const std::filesystem::path& path) noexcept;

// Isolated temporary workspace.
struct TemporaryWorkspaceData {
    std::filesystem::path root;
};

// Temporary workspace cleaned up automatically.
using TemporaryWorkspace =
    std::unique_ptr<TemporaryWorkspaceData, void (*)(TemporaryWorkspaceData*)>;

// Cleans up and frees the temporary workspace.
void remove_workspace(TemporaryWorkspaceData* workspace) noexcept;

// Creates an exclusive temporary workspace under the root directory.
std::expected<TemporaryWorkspace, Error>
make_workspace(const std::filesystem::path& root);

// Downloads an object to the specified destination.
std::expected<void, Error> download(transport::Transport& storage,
                                    std::string_view identifier,
                                    const std::filesystem::path& destination);
// Downloads a commit variant and distinguishes absence.
std::expected<void, Error>
download_commit_candidate(transport::Transport& storage,
                          const HeadReference& reference,
                          const std::filesystem::path& destination);

// Observed state of a marker.
enum class MarkerState {
    Absent,
    Valid,
    Invalid,
};

// Downloads and validates a remote marker.
std::expected<MarkerState, Error>
inspect_marker(transport::Transport& storage,
               const HeadReference& reference,
               const std::filesystem::path& workspace,
               std::size_t& sequence);

// Verifies the BLAKE3 identifier of the ciphertext.
std::expected<bool, Error> ciphertext_matches(const std::filesystem::path& path,
                                              std::string_view ciphertext_id);
// Enforces the maximum size of an encrypted commit.
std::expected<void, Error>
validate_ciphertext_size(const std::filesystem::path& path);

// Validation state of an encrypted variant.
enum class VariantState {
    Missing,
    InvalidCiphertext,
    InvalidCommit,
    Valid,
};

// Classified variant and decoded commit, when valid.
struct LoadedVariant {
    VariantState state = VariantState::Missing;
    std::optional<history::LoadedCommit> commit;
};

// Result of loading a variant.
using VariantResult = std::expected<LoadedVariant, Error>;

// Downloads, decrypts, and validates a variant.
VariantResult
try_load_variant(transport::Transport& storage,
                 std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                 const HeadReference& reference,
                 const std::filesystem::path& workspace,
                 std::size_t sequence);

// Returns the first valid variant of the commit.
std::expected<history::LoadedCommit, Error>
try_load_variants(transport::Transport& storage,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                  std::vector<HeadReference> references,
                  const std::filesystem::path& workspace,
                  std::size_t& sequence,
                  HeadReference* authenticated_reference = nullptr);

// Confirms that the remote commit matches the published one.
std::expected<void, Error>
verify_published_commit(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const history::Commit& expected,
                        const HeadReference& reference,
                        const std::filesystem::path& workspace,
                        std::size_t& sequence);

// Implements full publication of a commit.
PublishResult publish_impl(transport::Transport& storage,
                           std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                           const history::Commit& commit,
                           const std::filesystem::path& workspace_root);

// Implements full or scoped history loading.
LoadResult load_impl(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_root,
    std::optional<std::span<const std::string>> identifiers = std::nullopt,
    const KnownHistoryFrontier* frontier = nullptr,
    bool scoped = false,
    std::span<const std::string> trusted_marker_identifiers = {});

} // namespace kasumi::application::history_storage::detail

#endif
