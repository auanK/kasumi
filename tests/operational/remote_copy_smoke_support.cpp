#include "remote_copy_smoke_support.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <set>
#include <utility>

namespace kasumi::operational::remote_copy_smoke {
namespace {

bool safe_relative_identifier(std::string_view identifier) noexcept {
    if (identifier.empty() || identifier.front() == '/' ||
        identifier.find_first_of("\\:") != std::string_view::npos) {
        return false;
    }
    std::size_t begin = 0;
    while (begin <= identifier.size()) {
        const auto end = identifier.find('/', begin);
        const auto component = identifier.substr(
            begin,
            end == std::string_view::npos ? identifier.size() - begin
                                          : end - begin);
        if (component.empty() || component == "." || component == ".." ||
            std::isspace(static_cast<unsigned char>(component.front())) != 0 ||
            std::isspace(static_cast<unsigned char>(component.back())) != 0 ||
            std::any_of(component.begin(), component.end(), [](char value) {
                return static_cast<unsigned char>(value) < 0x20U ||
                       static_cast<unsigned char>(value) == 0x7fU;
            })) {
            return false;
        }
        if (end == std::string_view::npos) {
            break;
        }
        begin = end + 1;
    }
    return true;
}

bool valid_child(std::string_view child) noexcept {
    constexpr std::string_view prefix = "kasumi-copy-smoke-";
    if (!child.starts_with(prefix) || child.size() != prefix.size() + 32) {
        return false;
    }
    return std::all_of(child.begin() +
                           static_cast<std::ptrdiff_t>(prefix.size()),
                       child.end(),
                       [](char value) {
                           return (value >= '0' && value <= '9') ||
                                  (value >= 'a' && value <= 'f');
                       });
}

void replace_all(std::string& value,
                 std::string_view secret,
                 std::string_view replacement) {
    if (secret.empty()) {
        return;
    }
    std::size_t position = 0;
    while ((position = value.find(secret, position)) != std::string::npos) {
        value.replace(position, secret.size(), replacement);
        position += replacement.size();
    }
}

CleanupResult refused(std::string detail,
                      std::optional<transport::ErrorCode> code = std::nullopt) {
    return CleanupResult{.result = "refused",
                         .detail = std::move(detail),
                         .error_category = code};
}

nlohmann::json error_category_json(
    const std::optional<transport::ErrorCode>& code) {
    return code ? nlohmann::json(std::string{transport::error_code_name(*code)})
                : nlohmann::json(nullptr);
}

bool valid_sha256(std::string_view hash) noexcept {
    return hash.size() == 64 &&
           std::all_of(hash.begin(), hash.end(), [](unsigned char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f') ||
                      (character >= 'A' && character <= 'F');
           });
}

} // namespace

SmokeStatus classify(const CopySmokeOutcome& outcome) noexcept {
    if (outcome.required_operation_failed) {
        return SmokeStatus::Failed;
    }
    if (outcome.copy_unsupported || outcome.source_hash_unsupported ||
        outcome.destination_hash_unsupported) {
        return SmokeStatus::Unsupported;
    }
    return outcome.native_copy_succeeded && outcome.source_hash_valid &&
                   outcome.destination_hash_valid && outcome.hashes_match &&
                   outcome.destination_bytes_match && outcome.source_remains &&
                   outcome.cleanup_succeeded
               ? SmokeStatus::Pass
               : SmokeStatus::Failed;
}

std::string_view status_name(SmokeStatus status) noexcept {
    switch (status) {
        case SmokeStatus::Pass:
            return "PASS";
        case SmokeStatus::Unsupported:
            return "UNSUPPORTED";
        case SmokeStatus::Failed:
            return "FAILED";
    }
    return "FAILED";
}

std::array<std::chrono::milliseconds, 6> readiness_schedule() noexcept {
    constexpr std::array increments{std::chrono::milliseconds{0},
                                    std::chrono::milliseconds{250},
                                    std::chrono::milliseconds{500},
                                    std::chrono::milliseconds{1000},
                                    std::chrono::milliseconds{2000},
                                    std::chrono::milliseconds{4000}};
    auto elapsed = std::chrono::milliseconds{0};
    std::array<std::chrono::milliseconds, increments.size()> schedule{};
    for (std::size_t index = 0; index < increments.size(); ++index) {
        elapsed += increments[index];
        schedule[index] = elapsed;
    }
    return schedule;
}

ReadinessClassification classify_readiness(
    std::span<const ReadinessAttempt> attempts,
    std::chrono::milliseconds maximum_elapsed) {
    if (attempts.empty()) {
        return ReadinessClassification::Failed;
    }
    for (const auto& attempt : attempts) {
        if (attempt.attempt_index == 0 ||
            attempt.elapsed_since_reference.count() < 0 ||
            attempt.elapsed_since_reference > maximum_elapsed ||
            attempt.presence == ReadinessPresence::Failed ||
            attempt.physical_hash == ReadinessHash::Failed ||
            attempt.physical_hash == ReadinessHash::Invalid) {
            return ReadinessClassification::Failed;
        }
    }
    for (const auto& attempt : attempts) {
        if (attempt.physical_hash == ReadinessHash::Unsupported) {
            return ReadinessClassification::Unsupported;
        }
        if (attempt.physical_hash == ReadinessHash::Valid) {
            if (!valid_sha256(attempt.sha256)) {
                return ReadinessClassification::Failed;
            }
            return attempt.attempt_index == 1
                       ? ReadinessClassification::Ready
                       : ReadinessClassification::ReadyAfterDelay;
        }
    }

    const auto schedule = readiness_schedule();
    const bool contradictory = attempts.size() == schedule.size() &&
                               attempts.back().elapsed_since_reference >=
                                   schedule.back() &&
                               attempts.back().presence ==
                                   ReadinessPresence::Present &&
                               std::all_of(
                                   attempts.begin(),
                                   attempts.end(),
                                   [](const ReadinessAttempt& attempt) {
                                       return attempt.physical_hash ==
                                                  ReadinessHash::ObjectNotFound;
                                   });
    return contradictory
               ? ReadinessClassification::FailedContradictoryVisibility
               : ReadinessClassification::Failed;
}

std::string_view readiness_classification_name(
    ReadinessClassification classification) noexcept {
    switch (classification) {
        case ReadinessClassification::Ready:
            return "READY";
        case ReadinessClassification::ReadyAfterDelay:
            return "READY_AFTER_DELAY";
        case ReadinessClassification::Unsupported:
            return "UNSUPPORTED";
        case ReadinessClassification::Failed:
            return "FAILED";
        case ReadinessClassification::FailedContradictoryVisibility:
            return "FAILED_CONTRADICTORY_VISIBILITY";
    }
    return "FAILED";
}

std::expected<RemoteParent, std::string>
parse_remote_parent(std::string_view location) {
    const auto separator = location.find(':');
    if (separator == std::string_view::npos || separator == 0 ||
        location.starts_with('/') || location.starts_with("\\\\") ||
        (separator == 1 && std::isalpha(
                               static_cast<unsigned char>(location.front())) !=
                               0)) {
        return std::unexpected("remote must use rclone remote:path syntax");
    }
    const auto remote_name = location.substr(0, separator);
    const auto directory = location.substr(separator + 1);
    if (remote_name.find_first_of("/\\:") != std::string_view::npos ||
        directory.find_first_of("\\:") != std::string_view::npos ||
        !safe_relative_identifier(directory)) {
        return std::unexpected("remote parent contains an unsafe path");
    }
    const auto valid = transport::validate_transport_location(location);
    if (!valid) {
        return std::unexpected(valid.error().message);
    }
    return RemoteParent{.location = std::string{location},
                        .remote_name = std::string{remote_name},
                        .directory = std::string{directory}};
}

std::expected<std::string, std::string>
child_namespace(std::string_view random_hex) {
    constexpr std::string_view prefix = "kasumi-copy-smoke-";
    if (random_hex.size() != 32 ||
        !std::all_of(random_hex.begin(), random_hex.end(), [](char value) {
            return (value >= '0' && value <= '9') ||
                   (value >= 'a' && value <= 'f');
        })) {
        return std::unexpected("namespace nonce must be 128-bit lowercase hex");
    }
    return std::string{prefix} + std::string{random_hex};
}

std::string sanitize_rc_message(std::string message,
                                std::string_view username,
                                std::string_view password) {
    replace_all(message, username, "<redacted>");
    replace_all(message, password, "<redacted>");
    return message;
}

std::expected<std::string, std::string>
child_location(const RemoteParent& parent, std::string_view child) {
    if (!valid_child(child)) {
        return std::unexpected("invalid generated child namespace");
    }
    return parent.location + "/" + std::string{child};
}

std::expected<void, transport::Error>
require_unused_child(transport::Transport& storage, std::string_view child) {
    if (!valid_child(child)) {
        return std::unexpected(transport::Error{
            .code = transport::ErrorCode::InvalidIdentifier,
            .message = "invalid generated child namespace"});
    }
    const auto listing = transport::list(storage, child);
    if (listing) {
        return std::unexpected(transport::Error{
            .code = transport::ErrorCode::InvalidIdentifier,
            .message = listing->empty()
                           ? "empty child listing is ambiguous; refusing to assume unused"
                           : "test child namespace already exists"});
    }
    if (listing.error().code == transport::ErrorCode::StorageNotFound) {
        return {};
    }
    return std::unexpected(listing.error());
}

bool identifier_in_child(std::string_view child,
                         std::string_view identifier) noexcept {
    if (!valid_child(child)) {
        return false;
    }
    const auto prefix = std::string{child} + "/";
    return identifier.starts_with(prefix) &&
           safe_relative_identifier(identifier.substr(prefix.size()));
}

CleanupResult cleanup_owned_child(
    transport::Transport& storage,
    std::string_view child,
    std::string_view owner_token,
    const std::vector<std::string>& object_identifiers,
    const std::filesystem::path& local_scratch) {
    constexpr std::string_view owner_name = "owner.marker";
    const auto owner_identifier = std::string{child} + "/" +
                                  std::string{owner_name};
    if (!valid_child(child) || owner_token.empty() ||
        !std::filesystem::is_directory(local_scratch) ||
        std::filesystem::is_symlink(local_scratch)) {
        return refused("cleanup scope or local scratch is invalid");
    }
    std::set<std::string> unique;
    for (const auto& identifier : object_identifiers) {
        if (!identifier_in_child(child, identifier) ||
            identifier == owner_identifier || !unique.insert(identifier).second) {
            return refused("cleanup target is duplicate or outside child");
        }
    }
    const auto marker_path = local_scratch / "owner-check.tmp";
    if (std::filesystem::exists(marker_path)) {
        return refused("ownership check path already exists");
    }
    auto marker_read = transport::get(storage, owner_name, marker_path);
    if (!marker_read) {
        return refused("could not verify cleanup ownership",
                       marker_read.error().code);
    }
    std::ifstream marker_input(marker_path, std::ios::binary);
    if (!marker_input) {
        return refused("could not read cleanup ownership marker");
    }
    const std::string observed{std::istreambuf_iterator<char>{marker_input}, {}};
    const bool marker_read_failed = marker_input.bad();
    marker_input.close();
    std::error_code ignored;
    std::filesystem::remove(marker_path, ignored);
    if (marker_read_failed || observed != owner_token) {
        return refused("ownership marker does not match this run");
    }

    std::vector<std::string> present;
    for (const auto& identifier : object_identifiers) {
        const auto relative = identifier.substr(child.size() + 1);
        const auto state = transport::presence(storage, relative);
        if (!state) {
            return refused("could not establish cleanup target state",
                           state.error().code);
        }
        if (*state == transport::Presence::Present) {
            present.push_back(relative);
        }
    }

    CleanupResult result{.result = "removed"};
    for (const auto& identifier : present) {
        const auto removed = transport::remove(storage, identifier);
        if (!removed) {
            return CleanupResult{.result = "failed",
                                 .detail = "failed to remove an owned child object",
                                 .removed_objects = result.removed_objects,
                                 .error_category = removed.error().code};
        }
        result.removed_objects +=
            *removed == transport::Removal::Removed ? 1U : 0U;
    }
    const auto marker_removed = transport::remove(storage, owner_name);
    if (!marker_removed) {
        return CleanupResult{.result = "failed",
                             .detail = "failed to remove ownership marker",
                             .removed_objects = result.removed_objects,
                             .error_category = marker_removed.error().code};
    }
    result.removed_objects +=
        *marker_removed == transport::Removal::Removed ? 1U : 0U;
    return result;
}

nlohmann::json to_json(const OperationRecord& operation) {
    return nlohmann::json{
        {"name", operation.name},
        {"result", operation.result},
        {"elapsed_ms", operation.elapsed_ms},
        {"error_category", error_category_json(operation.error_category)},
        {"error_message", operation.error_message},
    };
}

nlohmann::json to_json(const CleanupResult& cleanup) {
    return nlohmann::json{{"result", cleanup.result},
                          {"detail", cleanup.detail},
                          {"removed_objects", cleanup.removed_objects},
                          {"error_category",
                           error_category_json(cleanup.error_category)}};
}

nlohmann::json to_json(const ReadinessAttempt& attempt) {
    std::string_view presence_result = "ABSENT";
    if (attempt.presence == ReadinessPresence::Present) {
        presence_result = "PRESENT";
    } else if (attempt.presence == ReadinessPresence::Failed) {
        presence_result = "FAILED";
    }

    std::string_view hash_result = "OBJECT_NOT_FOUND";
    switch (attempt.physical_hash) {
        case ReadinessHash::Valid:
            hash_result = "SUCCESS";
            break;
        case ReadinessHash::ObjectNotFound:
            hash_result = "OBJECT_NOT_FOUND";
            break;
        case ReadinessHash::Unsupported:
            hash_result = "UNSUPPORTED";
            break;
        case ReadinessHash::Failed:
            hash_result = "FAILED";
            break;
        case ReadinessHash::Invalid:
            hash_result = "INVALID_SHA256";
            break;
    }

    return nlohmann::json{
        {"attempt_index", attempt.attempt_index},
        {"elapsed_since_reference_ms",
         attempt.elapsed_since_reference.count()},
        {"presence",
         {{"result", presence_result},
          {"error_category", error_category_json(attempt.presence_error)},
          {"error_message", attempt.presence_error_message}}},
        {"physical_hash",
         {{"result", hash_result},
          {"error_category",
           error_category_json(attempt.physical_hash_error)},
          {"error_message", attempt.physical_hash_error_message},
          {"sha256", attempt.physical_hash == ReadinessHash::Valid
                          ? nlohmann::json(attempt.sha256)
                          : nlohmann::json(nullptr)}}}};
}

} // namespace kasumi::operational::remote_copy_smoke
