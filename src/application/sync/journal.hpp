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

// Private directory for the current, incompatible journal format.
inline constexpr std::string_view journal_file_name = "transaction.bin.enc";

// Name of the incremental transaction log.
inline constexpr std::string_view journal_log_file_name = "transaction.log.enc";

// Suffix used during atomic writes.
inline constexpr std::string_view temporary_suffix = ".new";

// Defensive limit for decrypted payload.
inline constexpr std::uint64_t maximum_payload_size = 64ULL * 1024ULL * 1024ULL;

// Final, temporary, and log paths for the journal.
struct Paths {
    std::filesystem::path final_path;
    std::filesystem::path temporary_path;
    std::filesystem::path log_path;
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

enum class SaveMode {
    Advance,
    Rollback
};

// Confirms an authenticated snapshot or incremental delta.
std::expected<void, std::string>
save(const Paths& paths,
     const transaction::Record& record,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
     SaveMode mode = SaveMode::Advance);

// Loads and validates the journal, if present.
std::expected<std::optional<transaction::Record>, std::string>
load(const Paths& paths, std::span<const std::uint8_t, crypto::KEY_SIZE> key);

// Durably retires the complete journal before physical cleanup.
std::expected<void, std::string>
clear(const Paths& paths, std::span<const std::uint8_t, crypto::KEY_SIZE> key);

} // namespace kasumi::application::sync::journal

#endif
