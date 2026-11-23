#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_ACTIVITY_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_ACTIVITY_HPP

#include "application/history_storage/epoch.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "crypto/key_derivation.hpp"
#include "transport/transport.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::history_storage::activity {

inline constexpr std::size_t event_id_byte_count = 16;
inline constexpr std::size_t event_id_hex_size = 32;
inline constexpr std::size_t machine_id_byte_count = 16;
inline constexpr std::size_t machine_id_hex_size = 32;
inline constexpr std::size_t maximum_machine_name_bytes = 128;
inline constexpr std::size_t maximum_stage_bytes = 64;
inline constexpr std::size_t maximum_detail_bytes = 256;
inline constexpr std::size_t maximum_encoded_size = 4096;
inline constexpr std::size_t maximum_activity_object_count = 1024;

enum class ActivityOperation : std::uint8_t {
    Fsck = 1,
    GarbageCollect = 2,
    RemoveWriter = 3,
    RemoveBarrier = 4,
};

enum class ActivityOutcome : std::uint8_t {
    Succeeded = 1,
    IssuesFound = 2,
    Blocked = 3,
    Cancelled = 4,
    Failed = 5,
    Uncertain = 6,
};

inline constexpr std::uint32_t flag_analysis_only = 1U << 0U;
inline constexpr std::uint32_t flag_barrier_already_absent = 1U << 1U;
inline constexpr std::uint32_t flag_barrier_release_failed = 1U << 2U;
inline constexpr std::uint32_t flag_mutation_uncertain = 1U << 3U;

struct ActivityRecord {
    std::string event_id;
    ActivityOperation operation = ActivityOperation::Fsck;
    ActivityOutcome outcome = ActivityOutcome::Succeeded;
    std::array<std::uint8_t, machine_id_byte_count> machine_id{};
    std::string machine_name;
    std::int64_t started_at = 0;
    std::int64_t finished_at = 0;
    std::uint64_t duration_ms = 0;
    std::uint64_t metric_primary = 0;
    std::uint64_t metric_secondary = 0;
    std::uint64_t metric_bytes = 0;
    std::uint32_t flags = 0;
    std::string stage;
    std::string detail;

    bool operator==(const ActivityRecord&) const noexcept = default;
};

struct Reference {
    std::int64_t finished_at = 0;
    std::string event_id;

    bool operator==(const Reference&) const noexcept = default;
};

struct LoadedActivity {
    std::string identifier;
    ActivityRecord record;

    bool operator==(const LoadedActivity&) const noexcept = default;
};

struct ActivityInventory {
    std::vector<LoadedActivity> valid;
    std::vector<std::string> invalid_objects;
};

// Sanitizes arbitrary diagnostic text into bounded valid UTF-8 without control
// characters so encoded activity records remain strictly decodable.
std::string sanitize_text(std::string_view raw, std::size_t max_bytes);

bool valid_record(const ActivityRecord& record) noexcept;

std::expected<std::string, Error> object_identifier(const RemoteLayout& layout,
                                                    std::int64_t finished_at,
                                                    std::string_view event_id);

std::optional<Reference> parse_object_identifier(const RemoteLayout& layout,
                                                 std::string_view identifier);

std::expected<std::vector<std::uint8_t>, Error>
encode(const ActivityRecord& record);

std::expected<ActivityRecord, Error>
decode(std::span<const std::uint8_t> bytes);

// Encrypts with FilePurpose::Activity and uploads an immutable KACT v1 record.
std::expected<std::string, Error>
publish(transport::Transport& storage,
        const RemoteLayout& layout,
        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
        const ActivityRecord& record,
        const std::filesystem::path& workspace_root);

// Lists, downloads, authenticates, and decodes remote operational records.
std::expected<ActivityInventory, Error>
load_all(transport::Transport& storage,
         const RemoteLayout& layout,
         std::span<const std::uint8_t, crypto::KEY_SIZE> key,
         const std::filesystem::path& workspace_root,
         std::optional<std::span<const std::string>> known_identifiers =
             std::nullopt);

// Selects old activity identifiers eligible for GC removal under retention
// policy aligned with sync/epoch history retention, keeping recent depth, age
// window, and the latest Succeeded event per (machine_id, operation).
std::vector<std::string> plan_pruning(std::span<const LoadedActivity> valid,
                                      const epoch::RetentionPolicy& policy,
                                      std::int64_t reference_now);

} // namespace kasumi::application::history_storage::activity

#endif
