#ifndef KASUMI_APPLICATION_SYNC_JOURNAL_HPP
#define KASUMI_APPLICATION_SYNC_JOURNAL_HPP

#include "core/transaction/types.hpp"
#include "crypto/file_crypto.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace kasumi::application::sync::journal {

// Name of the persisted transaction journal.
inline constexpr std::string_view journal_file_name = "transaction.bin.enc";

// Suffix used during atomic writes.
inline constexpr std::string_view temporary_suffix = ".new";

// Defensive limit for decrypted payload.
inline constexpr std::uint64_t maximum_payload_size = 64ULL * 1024ULL * 1024ULL;

// Final and temporary paths for the journal.
struct Paths {
    std::filesystem::path final_path;
    std::filesystem::path temporary_path;
};

// Resolves journal paths within the profile.
std::expected<Paths, std::string>
make_paths(const std::filesystem::path& profile_directory);

// Creates the initial transaction record.
std::expected<transaction::Record, std::string>
create_record(std::uint64_t local_generation,
              std::uint64_t storage_generation,
              SyncPlan plan,
              bool publication_required = true,
              std::string observed_head_id = {});

// Persists the encrypted journal via atomic replacement.
std::expected<void, std::string>
save(const Paths& paths,
     const transaction::Record& record,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key);

// Loads and validates the journal, if present.
std::expected<std::optional<transaction::Record>, std::string>
load(const Paths& paths, std::span<const std::uint8_t, crypto::KEY_SIZE> key);

// Removes final and temporary journal files.
std::expected<void, std::string> clear(const Paths& paths);

// Discards the temporary file without propagating failures.
void discard_temporary(const Paths& paths) noexcept;

} // namespace kasumi::application::sync::journal

#endif
