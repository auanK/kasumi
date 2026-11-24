#ifndef KASUMI_APPLICATION_SYNC_JOURNAL_HPP
#define KASUMI_APPLICATION_SYNC_JOURNAL_HPP

#include "core/transaction/types.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/file_fingerprint.hpp"

#include <cstddef>
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

enum class SessionState : std::uint8_t {
    Uninitialized,
    Confirmed,
    Invalid,
    Retired
};

// Owned cache of authenticated disk state; callers observe via free functions.
struct Session {
    SessionState state = SessionState::Uninitialized;
    Paths paths{};
    std::string operation_id{};
    std::array<std::byte, 32> key_identity{};
    std::optional<transaction::Record> confirmed_record{};
    std::array<std::byte, 32> tip_chain{};
    std::uint64_t tip_bytes = 0;
    std::uint64_t tip_count = 0;
    std::array<std::byte, 32> tip_snapshot{};
    std::optional<platform::FileFingerprint> snapshot_fingerprint{};
    std::optional<platform::FileFingerprint> log_fingerprint{};
    std::uint64_t snapshot_bytes = 0;

    Session() = default;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
};

[[nodiscard]] inline SessionState
session_status(const Session& session) noexcept {
    return session.state;
}

[[nodiscard]] inline const transaction::Record*
confirmed_record(const Session& session) noexcept {
    return session.confirmed_record ? &*session.confirmed_record : nullptr;
}

[[nodiscard]] inline std::string_view
session_operation(const Session& session) noexcept {
    return session.operation_id;
}

[[nodiscard]] inline std::uint64_t
confirmed_bytes(const Session& session) noexcept {
    return session.tip_bytes;
}

[[nodiscard]] inline std::uint64_t
confirmed_count(const Session& session) noexcept {
    return session.tip_count;
}

[[nodiscard]] inline bool is_session_valid(const Session& session) noexcept {
    return session.state == SessionState::Confirmed &&
           session.confirmed_record.has_value();
}

inline void invalidate_session(Session& session) noexcept {
    if (session.state != SessionState::Retired) {
        session.state = SessionState::Invalid;
    }
    session.confirmed_record.reset();
    session.tip_bytes = 0;
    session.tip_count = 0;
    session.tip_chain.fill(std::byte{});
    session.tip_snapshot.fill(std::byte{});
    session.snapshot_fingerprint.reset();
    session.log_fingerprint.reset();
}

// Confirms an authenticated snapshot or incremental delta.
// If session is provided and valid, executes fast-path delta persistence
// without full replay.
std::expected<void, std::string>
save(const Paths& paths,
     const transaction::Record& record,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
     SaveMode mode = SaveMode::Advance,
     Session* session = nullptr);

// Loads and validates the journal, if present.
// If session is provided, rehydrates the session with the loaded durable state.
std::expected<std::optional<transaction::Record>, std::string>
load(const Paths& paths,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
     Session* session = nullptr);

// Durably retires the complete journal before physical cleanup.
// If session is provided, marks the session as Retired.
std::expected<void, std::string>
clear(const Paths& paths,
      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
      Session* session = nullptr);

enum class InspectionResult : std::uint8_t {
    Absent,
    Active,
    Retired,
    Corrupted
};

// Passively inspects the journal artifacts without modifying files,
// performing recovery, clearing, or creating sidecars.
InspectionResult inspect(const Paths& paths,
                         std::span<const std::uint8_t, crypto::KEY_SIZE> key);

} // namespace kasumi::application::sync::journal

#endif
