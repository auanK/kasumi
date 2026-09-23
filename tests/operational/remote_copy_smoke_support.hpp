#ifndef KASUMI_REMOTE_COPY_SMOKE_SUPPORT_HPP
#define KASUMI_REMOTE_COPY_SMOKE_SUPPORT_HPP

#include "transport/transport.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::operational::remote_copy_smoke {

struct RemoteParent {
    std::string location;
    std::string remote_name;
    std::string directory;
};

struct OperationRecord {
    std::string name;
    std::string result;
    double elapsed_ms = 0.0;
    std::optional<transport::ErrorCode> error_category;
    std::string error_message;
};

struct CleanupResult {
    std::string result;
    std::string detail;
    std::size_t removed_objects = 0;
    std::optional<transport::ErrorCode> error_category;
};

enum class ReadinessPresence { Present, Absent, Failed };
enum class ReadinessHash { Valid, ObjectNotFound, Unsupported, Failed, Invalid };
enum class ReadinessClassification {
    Ready,
    ReadyAfterDelay,
    Unsupported,
    Failed,
    FailedContradictoryVisibility,
};

struct ReadinessAttempt {
    std::size_t attempt_index = 0;
    std::chrono::milliseconds elapsed_since_reference{};
    ReadinessPresence presence = ReadinessPresence::Absent;
    std::optional<transport::ErrorCode> presence_error;
    std::string presence_error_message;
    ReadinessHash physical_hash = ReadinessHash::ObjectNotFound;
    std::optional<transport::ErrorCode> physical_hash_error;
    std::string physical_hash_error_message;
    std::string sha256;
};

enum class SmokeStatus { Pass, Unsupported, Failed };

struct CopySmokeOutcome {
    bool required_operation_failed = false;
    bool copy_unsupported = false;
    bool source_hash_unsupported = false;
    bool destination_hash_unsupported = false;
    bool native_copy_succeeded = false;
    bool source_hash_valid = false;
    bool destination_hash_valid = false;
    bool hashes_match = false;
    bool destination_bytes_match = false;
    bool source_remains = false;
    bool cleanup_succeeded = false;
    bool fallback_succeeded = false;
};

SmokeStatus classify(const CopySmokeOutcome& outcome) noexcept;
std::string_view status_name(SmokeStatus status) noexcept;
std::array<std::chrono::milliseconds, 6> readiness_schedule() noexcept;
ReadinessClassification classify_readiness(
    std::span<const ReadinessAttempt> attempts,
    std::chrono::milliseconds maximum_elapsed);
std::string_view readiness_classification_name(
    ReadinessClassification classification) noexcept;

std::expected<RemoteParent, std::string>
parse_remote_parent(std::string_view location);

std::expected<std::string, std::string>
child_namespace(std::string_view random_hex);

std::expected<std::string, std::string>
child_location(const RemoteParent& parent, std::string_view child);

std::expected<void, transport::Error>
require_unused_child(transport::Transport& storage, std::string_view child);

bool identifier_in_child(std::string_view child,
                         std::string_view identifier) noexcept;

CleanupResult cleanup_owned_child(
    transport::Transport& storage,
    std::string_view child,
    std::string_view owner_token,
    const std::vector<std::string>& object_identifiers,
    const std::filesystem::path& local_scratch);

nlohmann::json to_json(const OperationRecord& operation);
nlohmann::json to_json(const CleanupResult& cleanup);
nlohmann::json to_json(const ReadinessAttempt& attempt);

} // namespace kasumi::operational::remote_copy_smoke

#endif
