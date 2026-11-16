#include "../detail.hpp"
#include "detail.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::transport::rclone_detail {
namespace {

constexpr std::size_t maximum_response_size = 64 * 1024;
constexpr std::size_t maximum_list_response_size = 64 * 1024 * 1024;
constexpr std::size_t maximum_check_response_size = 64 * 1024 * 1024;
constexpr auto quick_timeout = std::chrono::seconds{30};
// Drive DELETE calls show 5-20 s tails; 120 s avoids ambiguous client timeouts.
constexpr auto remove_timeout = std::chrono::seconds{120};
constexpr auto control_read_deadline = std::chrono::minutes{2};
constexpr auto transfer_timeout = std::chrono::minutes{30};

using detail::make_error;

Error invalid_context_error() {
    return make_error(ErrorCode::InvalidContext, "RC session is not ready");
}

Error invalid_identifier_error() {
    return make_error(ErrorCode::InvalidIdentifier,
                      "invalid object identifier");
}

Error filesystem_error(const std::error_code& error) {
    return make_error(ErrorCode::Io, error.message(), error.value());
}

bool valid_identifier(std::string_view identifier) noexcept {
    return detail::valid_relative_identifier(identifier, false);
}

bool valid_sha256(std::string_view value) noexcept {
    return value.size() == 64 && std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f') ||
                      (character >= 'A' && character <= 'F');
           });
}

bool valid_batch_identifier(std::string_view identifier) noexcept {
    return identifier.find_first_of("\r\n") == std::string_view::npos &&
           detail::valid_relative_identifier(identifier, true);
}

std::string ascii_lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

nlohmann::json stat_opt(bool files_only,
                        std::optional<bool> recurse = std::nullopt) {
    nlohmann::json opt{
        {"filesOnly", files_only},
        {"noModTime", true},
        {"noMimeType", true},
    };
    if (recurse.has_value()) {
        opt["recurse"] = *recurse;
    }
    return opt;
}

PresenceResult parse_stat_presence(const nlohmann::json& item,
                                   std::string_view invalid_message,
                                   std::string_view directory_message) {
    if (item.is_null()) {
        return Presence::Absent;
    }
    if (!item.is_object() ||
        (item.contains("IsDir") && !item.at("IsDir").is_boolean())) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          std::string{invalid_message}));
    }
    if (item.value("IsDir", false)) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          std::string{directory_message}));
    }
    return Presence::Present;
}

std::expected<State*, Error>
require_ready(void* context,
              std::optional<std::string_view> identifier = std::nullopt) {
    auto* state = static_cast<State*>(context);
    if (state == nullptr || !state->ready ||
        state->configuration.remote_name.empty()) {
        return std::unexpected(invalid_context_error());
    }
    if (identifier && !valid_identifier(*identifier)) {
        return std::unexpected(invalid_identifier_error());
    }
    return state;
}

std::string join_remote_path(std::string_view root, std::string_view suffix) {
    while (root.ends_with('/')) {
        root.remove_suffix(1);
    }
    while (suffix.starts_with('/')) {
        suffix.remove_prefix(1);
    }
    while (suffix.ends_with('/')) {
        suffix.remove_suffix(1);
    }
    if (root.empty()) {
        return std::string{suffix};
    }
    if (suffix.empty()) {
        return std::string{root};
    }
    return std::string{root} + "/" + std::string{suffix};
}

std::string rooted_remote_fs(const State& state) {
    return state.configuration.remote_name + ":" +
           state.configuration.remote_root;
}

std::expected<nlohmann::json, Error>
request_json(State& state,
             std::string_view endpoint,
             const nlohmann::json& request,
             std::size_t response_limit,
             std::chrono::milliseconds read_timeout,
             bool retry_transient_reads = false) {
    const auto body = request.dump();
    const auto response =
        retry_transient_reads
            ? post_rc_read_only(
                  state, endpoint, body, response_limit, read_timeout)
            : post_rc(state, endpoint, body, response_limit, read_timeout);
    if (!response) {
        return std::unexpected(response.error());
    }

    try {
        return nlohmann::json::parse(*response);
    } catch (const std::exception&) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure,
            std::string{"invalid "} + std::string{endpoint} + " response"));
    }
}

std::expected<nlohmann::json, Error>
request_read_json(State& state,
                  std::string_view endpoint,
                  const nlohmann::json& request,
                  std::size_t response_limit,
                  std::chrono::milliseconds deadline) {
    return request_json(
        state, endpoint, request, response_limit, deadline, true);
}

std::expected<std::vector<std::string>, Error>
check_entries(const nlohmann::json& response,
              std::string_view name,
              const std::unordered_set<std::string>& expected,
              std::unordered_set<std::string>& seen) {
    if (!response.contains(name) || !response.at(name).is_array()) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure,
            "operations/check response missing list " + std::string{name}));
    }

    std::vector<std::string> entries;
    for (const auto& item : response.at(name)) {
        if (!item.is_string()) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "operations/check response contains invalid entry"));
        }
        auto identifier = item.get<std::string>();
        if (!expected.contains(identifier) || !seen.insert(identifier).second) {
            return std::unexpected(make_error(
                ErrorCode::ProtocolFailure,
                "operations/check response contains unexpected identifier"));
        }
        entries.push_back(std::move(identifier));
    }
    return entries;
}

bool unsupported_endpoint(const Error& error,
                          std::string_view endpoint) noexcept {
    return error.code == ErrorCode::ProtocolFailure &&
           error.native_code == 404 &&
           (error.message.find(endpoint) != std::string::npos ||
            error.message.find("method not found") != std::string::npos);
}

std::expected<nlohmann::json, Error>
run_job_batch(State& state,
              const nlohmann::json& inputs,
              std::size_t concurrency,
              std::size_t response_limit,
              std::chrono::milliseconds timeout,
              bool read_only) {
    nlohmann::json request{
        {"inputs", inputs},
        {"concurrency", concurrency},
    };
    auto response = request_json(
        state, "job/batch", request, response_limit, timeout, read_only);
    if (!response) {
        if (unsupported_endpoint(response.error(), "job/batch")) {
            return std::unexpected(
                make_error(ErrorCode::Unsupported,
                           "rclone does not support job/batch",
                           response.error().native_code));
        }
        return std::unexpected(response.error());
    }
    return response;
}

std::expected<int, Error>
parse_job_batch_status(const nlohmann::json& status_json,
                       std::string_view operation_name) {
    if (!status_json.is_number_integer()) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          std::string("invalid ") +
                                              std::string(operation_name) +
                                              " job/batch result status"));
    }
    const auto in_range = [](auto value) noexcept {
        return value >= 100 && value <= 599;
    };
    if (status_json.is_number_unsigned()) {
        if (const auto val = status_json.get<std::uint64_t>(); in_range(val)) {
            return static_cast<int>(val);
        }
    } else if (const auto val = status_json.get<std::int64_t>();
               in_range(val)) {
        return static_cast<int>(val);
    }
    return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                      std::string("out-of-range ") +
                                          std::string(operation_name) +
                                          " job/batch result status"));
}

std::expected<std::filesystem::path, Error>
absolute_path(const std::filesystem::path& path) {
    std::error_code error;
    auto absolute = std::filesystem::absolute(path, error);
    if (error) {
        return std::unexpected(filesystem_error(error));
    }
    return absolute;
}

Result ensure_parent_directory(const std::filesystem::path& path) {
    const auto parent = path.parent_path();
    if (parent.empty()) {
        return std::unexpected(make_error(
            ErrorCode::InvalidContext, "local path has no parent directory"));
    }

    std::error_code error;
    std::filesystem::create_directories(parent, error);
    if (error) {
        return std::unexpected(filesystem_error(error));
    }
    return {};
}

Result require_regular_source(const std::filesystem::path& source) {
    std::error_code error;
    const bool regular = std::filesystem::is_regular_file(source, error);
    if (error) {
        if (error == std::errc::no_such_file_or_directory) {
            return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                              "source file does not exist"));
        }
        return std::unexpected(filesystem_error(error));
    }
    if (!regular) {
        return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                          "source file does not exist"));
    }
    return {};
}

std::expected<nlohmann::json, Error>
stat_remote(State& state, std::string_view remote, bool files_only = true) {
    return request_read_json(state,
                             "operations/stat",
                             nlohmann::json{
                                 {"fs", rooted_remote_fs(state)},
                                 {"remote", remote},
                                 {"opt", stat_opt(files_only)},
                             },
                             maximum_response_size,
                             control_read_deadline);
}

bool not_found(const Error& error) noexcept {
    return error.code == ErrorCode::ProtocolFailure &&
           (error.native_code == 404 ||
            error.message.find("not found") != std::string::npos);
}

struct SplitLocalPath {
    std::filesystem::path absolute;
    std::string parent;
    std::string name;
};

std::expected<SplitLocalPath, Error>
split_local_path(const std::filesystem::path& path,
                 std::string_view invalid_message) {
    const auto absolute = absolute_path(path);
    if (!absolute) {
        return std::unexpected(absolute.error());
    }
    auto name = platform::path::to_utf8(absolute->filename());
    auto parent = platform::path::to_utf8(absolute->parent_path());
    if (name.empty() || parent.empty()) {
        return std::unexpected(make_error(ErrorCode::InvalidContext,
                                          std::string{invalid_message}));
    }
    return SplitLocalPath{
        .absolute = *absolute,
        .parent = std::move(parent),
        .name = std::move(name),
    };
}

Result copyfile_object(State& state,
                       std::string_view src_fs,
                       std::string_view src_remote,
                       std::string_view dst_fs,
                       std::string_view dst_remote,
                       std::string_view not_found_message = {}) {
    const auto copied = request_json(state,
                                     "operations/copyfile",
                                     nlohmann::json{
                                         {"srcFs", std::string{src_fs}},
                                         {"srcRemote", std::string{src_remote}},
                                         {"dstFs", std::string{dst_fs}},
                                         {"dstRemote", std::string{dst_remote}},
                                     },
                                     maximum_response_size,
                                     transfer_timeout);
    if (!copied) {
        if (!not_found_message.empty() && not_found(copied.error())) {
            return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                              std::string{not_found_message}));
        }
        return std::unexpected(copied.error());
    }
    return {};
}

PresenceResult rclone_presence(void* context, std::string_view identifier);

Result rclone_initialize(void* context) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }

    const auto created = request_json(
        **state,
        "operations/mkdir",
        nlohmann::json{{"fs", rooted_remote_fs(**state)}, {"remote", ""}},
        maximum_response_size,
        quick_timeout);
    if (!created) {
        return std::unexpected(created.error());
    }
    return {};
}

Result rclone_put(void* context,
                  const std::filesystem::path& source,
                  std::string_view identifier) {
    auto state = require_ready(context, identifier);
    if (!state) {
        return std::unexpected(state.error());
    }

    const auto local = split_local_path(source, "invalid source file");
    if (!local) {
        return std::unexpected(local.error());
    }
    if (const auto source_file = require_regular_source(local->absolute);
        !source_file) {
        return source_file;
    }

    return copyfile_object(**state,
                           local->parent,
                           local->name,
                           rooted_remote_fs(**state),
                           identifier);
}

Result sync_copy_batch(State& state,
                       std::string_view src_fs,
                       std::string_view dst_fs,
                       std::span<const std::string> identifiers,
                       std::size_t max_parallel_transfers,
                       nlohmann::json base_config,
                       bool read_only) {
    nlohmann::json include_rules = nlohmann::json::array();
    for (const auto& identifier : identifiers) {
        // Reject rclone filter glob/brace metacharacters so an identifier
        // cannot expand an IncludeRule beyond its exact relative path.
        if (!valid_identifier(identifier) ||
            identifier.find_first_of("*?[]{}") != std::string::npos) {
            return std::unexpected(invalid_identifier_error());
        }
        include_rules.push_back("/" + identifier);
    }
    nlohmann::json payload = {
        {"srcFs", std::string{src_fs}},
        {"dstFs", std::string{dst_fs}},
        {"createEmptySrcDirs", false},
        {"_filter", {{"IncludeRule", include_rules}}},
    };
    if (max_parallel_transfers > 0) {
        base_config["Transfers"] = max_parallel_transfers;
    }
    if (!base_config.empty()) {
        payload["_config"] = std::move(base_config);
    }
    const auto copied = request_json(state,
                                     "sync/copy",
                                     payload,
                                     maximum_response_size,
                                     transfer_timeout,
                                     read_only);
    if (!copied) {
        return std::unexpected(copied.error());
    }
    return {};
}

Result rclone_put_batch(void* context, const PutBatch& batch) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (batch.identifiers.empty()) {
        return {};
    }
    const auto absolute_source = absolute_path(batch.source_root);
    if (!absolute_source) {
        return std::unexpected(absolute_source.error());
    }
    return sync_copy_batch(**state,
                           platform::path::to_utf8(*absolute_source),
                           rooted_remote_fs(**state),
                           batch.identifiers,
                           batch.max_parallel_transfers,
                           {{"NoTraverse", true}, {"NoUpdateModTime", true}},
                           false);
}

Result rclone_get(void* context,
                  std::string_view identifier,
                  const std::filesystem::path& destination) {
    auto state = require_ready(context, identifier);
    if (!state) {
        return std::unexpected(state.error());
    }

    const auto local =
        split_local_path(destination, "invalid local destination");
    if (!local) {
        return std::unexpected(local.error());
    }
    std::error_code error;
    const auto pre_status =
        std::filesystem::symlink_status(local->absolute, error);
    if (error && error != std::errc::no_such_file_or_directory) {
        return std::unexpected(filesystem_error(error));
    }
    if (std::filesystem::is_symlink(pre_status) ||
        std::filesystem::is_directory(pre_status)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "local destination cannot be a symlink or directory"));
    }
    if (const auto parent = ensure_parent_directory(local->absolute); !parent) {
        return parent;
    }

    if (const auto copied = copyfile_object(**state,
                                            rooted_remote_fs(**state),
                                            identifier,
                                            local->parent,
                                            local->name,
                                            "remote object does not exist");
        !copied) {
        return copied;
    }

    error.clear();
    const auto post_status =
        std::filesystem::symlink_status(local->absolute, error);
    if (error) {
        return std::unexpected(filesystem_error(error));
    }
    if (std::filesystem::is_symlink(post_status) ||
        !std::filesystem::is_regular_file(post_status)) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "local destination did not become regular file"));
    }
    return {};
}

Result rclone_get_batch(void* context, const GetBatch& batch) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (!batch.source_prefix.empty() &&
        !valid_identifier(batch.source_prefix)) {
        return std::unexpected(invalid_identifier_error());
    }
    if (batch.identifiers.empty()) {
        return {};
    }
    const auto absolute_destination = absolute_path(batch.destination_root);
    if (!absolute_destination) {
        return std::unexpected(absolute_destination.error());
    }
    return sync_copy_batch(
        **state,
        batch.source_prefix.empty()
            ? rooted_remote_fs(**state)
            : join_remote_path(rooted_remote_fs(**state), batch.source_prefix),
        platform::path::to_utf8(*absolute_destination),
        batch.identifiers,
        batch.max_parallel_transfers,
        nlohmann::json::object(),
        true);
}

ListingResult parse_list_response_json(const nlohmann::json& response,
                                       std::string_view remote_prefix = {}) {
    if (!response.is_object() || !response.contains("list") ||
        !response["list"].is_array()) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "invalid operations/list response"));
    }

    std::vector<std::string> identifiers;
    std::unordered_set<std::string> seen;
    for (const auto& item : response["list"]) {
        if (!item.is_object() || !item.contains("Path") ||
            !item["Path"].is_string()) {
            return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                              "invalid operations/list item"));
        }
        auto identifier = item["Path"].get<std::string>();
        if (!remote_prefix.empty()) {
            const auto prefix = std::string{remote_prefix} + "/";
            if (identifier.starts_with(prefix)) {
                identifier.erase(0, prefix.size());
            }
        }
        if (!valid_identifier(identifier)) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "operations/list returned invalid Path"));
        }
        if (!seen.insert(identifier).second) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "remote returned duplicate identifiers"));
        }
        identifiers.push_back(std::move(identifier));
    }
    std::ranges::sort(identifiers);
    return identifiers;
}

PresenceResult rclone_presence(void* context, std::string_view identifier) {
    auto state = require_ready(context, identifier);
    if (!state) {
        return std::unexpected(state.error());
    }

    const auto response = stat_remote(**state, identifier);
    if (!response) {
        if (not_found(response.error())) {
            return Presence::Absent;
        }
        return std::unexpected(response.error());
    }
    if (!response->is_object() || !response->contains("item")) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "invalid operations/stat response"));
    }
    return parse_stat_presence((*response)["item"],
                               "invalid operations/stat response",
                               "remote object is a directory");
}

ListingResult
list_remote_objects(void* context,
                    std::optional<std::string_view> prefix = std::nullopt) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (prefix && !valid_identifier(*prefix)) {
        return std::unexpected(invalid_identifier_error());
    }
    const std::string_view effective_prefix =
        prefix.value_or(std::string_view{});
    const auto response =
        request_read_json(**state,
                          "operations/list",
                          nlohmann::json{
                              {"fs", rooted_remote_fs(**state)},
                              {"remote", effective_prefix},
                              {"opt", stat_opt(true, effective_prefix.empty())},
                          },
                          maximum_list_response_size,
                          control_read_deadline);
    if (!response) {
        if (not_found(response.error())) {
            return std::unexpected(
                make_error(ErrorCode::StorageNotFound,
                           "remote objects directory does not exist"));
        }
        return std::unexpected(response.error());
    }
    return parse_list_response_json(*response, effective_prefix);
}

ListingResult rclone_list(void* context) {
    return list_remote_objects(context);
}

ListingResult rclone_list_prefix(void* context, std::string_view prefix) {
    return list_remote_objects(context, prefix);
}

std::expected<std::string, Error> rclone_physical_hash(
    void* context, std::string_view identifier, std::string_view algorithm) {
    auto state = require_ready(context, identifier);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (algorithm != "sha256" ||
        (*state)->sha256_unsupported.load(std::memory_order_relaxed)) {
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "rclone backend does not expose algorithm"));
    }

    const auto response =
        request_read_json(**state,
                          "operations/hashsumfile",
                          nlohmann::json{{"fs", rooted_remote_fs(**state)},
                                         {"remote", identifier},
                                         {"hashType", "SHA-256"}},
                          maximum_response_size,
                          control_read_deadline);
    if (!response) {
        if (response.error().code == ErrorCode::ProtocolFailure &&
            response.error().native_code == 404 &&
            response.error().message.find(
                "couldn't find method \"operations/hashsumfile\"") !=
                std::string::npos) {
            return std::unexpected(
                make_error(ErrorCode::Unsupported,
                           "rclone does not support operations/hashsumfile",
                           response.error().native_code));
        }
        if (not_found(response.error())) {
            return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                              "remote object does not exist"));
        }
        if (response.error().code == ErrorCode::Unsupported ||
            response.error().native_code == 400 ||
            response.error().native_code == 501 ||
            response.error().message.find("hash type not supported") !=
                std::string::npos) {
            (*state)->sha256_unsupported.store(true, std::memory_order_relaxed);
            return std::unexpected(
                make_error(ErrorCode::Unsupported,
                           "rclone backend does not expose algorithm",
                           response.error().native_code));
        }
        return std::unexpected(response.error());
    }
    if (!response->is_object() || !response->contains("hash") ||
        !response->at("hash").is_string() || !response->contains("hashType") ||
        !response->at("hashType").is_string()) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "rclone returned a malformed physical hash response"));
    }
    const auto returned_algorithm = response->at("hashType").get<std::string>();
    if (returned_algorithm != "sha256" && returned_algorithm != "SHA-256") {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "rclone returned a different physical hash algorithm"));
    }
    auto digest = response->at("hash").get<std::string>();
    if (!valid_sha256(digest)) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "rclone returned a malformed SHA-256 digest"));
    }
    return ascii_lower(std::move(digest));
}

PhysicalHashBatchResult parse_physical_hash_batch_response_json(
    const nlohmann::json& response, const PhysicalHashBatchRequest& request) {
    if (!response.is_object() || !response.contains("success") ||
        !response.at("success").is_boolean() ||
        !response.contains("hashType") ||
        !response.at("hashType").is_string()) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "invalid operations/check response"));
    }

    if (ascii_lower(response.at("hashType").get<std::string>()) != "sha256") {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "operations/check returned unexpected algorithm"));
    }

    std::unordered_set<std::string> expected;
    for (const auto& object : request.objects) {
        if (!expected.insert(object.identifier).second) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "duplicate identifiers in physical hash request"));
        }
    }

    std::unordered_set<std::string> seen;
    PhysicalHashBatchReport report;
    for (const auto& [name, destination] :
         {std::pair{"match", &report.matched},
          std::pair{"differ", &report.mismatched},
          std::pair{"missingOnDst", &report.missing},
          std::pair{"error", &report.errors}}) {
        auto entries = check_entries(response, name, expected, seen);
        if (!entries) {
            return std::unexpected(entries.error());
        }
        *destination = std::move(*entries);
    }

    const bool success = response.at("success").get<bool>();
    const bool has_failures = !report.mismatched.empty() ||
                              !report.missing.empty() || !report.errors.empty();
    if (seen.size() != expected.size() ||
        (success &&
         (has_failures || report.matched.size() != expected.size())) ||
        (!success && !has_failures)) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "inconsistent operations/check response"));
    }

    return report;
}

PhysicalHashBatchResult
rclone_physical_hash_batch(void* context,
                           const PhysicalHashBatchRequest& request) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (ascii_lower(request.algorithm) != "sha256" ||
        (*state)->sha256_unsupported.load(std::memory_order_relaxed)) {
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "rclone backend does not expose algorithm for batch"));
    }

    std::unordered_set<std::string> identifiers;
    std::vector<PhysicalHashExpectation> expectations;
    expectations.reserve(request.objects.size());
    for (const auto& object : request.objects) {
        if (!valid_batch_identifier(object.identifier) ||
            !identifiers.insert(object.identifier).second) {
            return std::unexpected(invalid_identifier_error());
        }
        if (!valid_sha256(object.expected_hash)) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "expected hash is not valid SHA-256"));
        }
        expectations.push_back(object);
    }

    auto root = absolute_path(request.scratch_root);
    if (!root) {
        return std::unexpected(root.error());
    }
    std::error_code status_error;
    const auto root_status =
        std::filesystem::symlink_status(*root, status_error);
    if (status_error || std::filesystem::is_symlink(root_status) ||
        !std::filesystem::is_directory(root_status)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "scratch_root is not a real local directory"));
    }

    std::ranges::sort(expectations, {}, &PhysicalHashExpectation::identifier);
    const auto manifest = *root / ".kasumi-batch-verify.sha256";
    const auto files = *root / ".kasumi-batch-verify.files";
    for (const auto& path : {manifest, files}) {
        const auto status = std::filesystem::symlink_status(path, status_error);
        if (status_error &&
            status_error != std::errc::no_such_file_or_directory) {
            return std::unexpected(filesystem_error(status_error));
        }
        if (!status_error && std::filesystem::exists(status)) {
            return std::unexpected(make_error(
                ErrorCode::InvalidContext,
                "verification manifest or file list already exists"));
        }
    }

    {
        std::ofstream output(manifest, std::ios::binary);
        if (!output) {
            return std::unexpected(make_error(
                ErrorCode::Io, "failed to create verification manifest"));
        }
        std::ofstream file_list(files, std::ios::binary);
        if (!file_list) {
            output.close();
            std::error_code ignored;
            std::filesystem::remove(manifest, ignored);
            return std::unexpected(make_error(
                ErrorCode::Io, "failed to create verification file list"));
        }
        for (const auto& object : expectations) {
            output << object.expected_hash << "  " << object.identifier << '\n';
            file_list << object.identifier << '\n';
        }
        output.close();
        file_list.close();
        if (!output || !file_list) {
            std::error_code ignored;
            std::filesystem::remove(manifest, ignored);
            std::filesystem::remove(files, ignored);
            return std::unexpected(make_error(
                ErrorCode::Io,
                "failed to write verification manifest or file list"));
        }
    }

    const auto manifest_parent = platform::path::to_utf8(*root);
    const auto response = request_read_json(
        **state,
        "operations/check",
        nlohmann::json{
            {"dstFs", rooted_remote_fs(**state)},
            {"checkFileHash", "SHA-256"},
            {"checkFileFs", manifest_parent},
            {"checkFileRemote", platform::path::to_utf8(manifest.filename())},
            {"oneWay", true},
            {"missingOnSrc", false},
            {"missingOnDst", true},
            {"match", true},
            {"differ", true},
            {"error", true},
            {"_config", {{"NoTraverse", true}}},
            // Restrict names: oneWay alone still scans the remote.
            {"_filter", {{"FilesFromRaw", {platform::path::to_utf8(files)}}}},
        },
        maximum_check_response_size,
        transfer_timeout);
    bool cleanup_failed = false;
    for (const auto& path : {manifest, files}) {
        std::error_code cleanup_error;
        if (!std::filesystem::remove(path, cleanup_error) || cleanup_error) {
            cleanup_failed = true;
        }
    }
    if (cleanup_failed) {
        return std::unexpected(
            make_error(ErrorCode::Io,
                       "failed to remove verification manifest or file list"));
    }
    if (!response) {
        if (unsupported_endpoint(response.error(), "operations/check") ||
            response.error().code == ErrorCode::Unsupported ||
            response.error().native_code == 400 ||
            response.error().native_code == 501) {
            (*state)->sha256_unsupported.store(true, std::memory_order_relaxed);
            return std::unexpected(
                make_error(ErrorCode::Unsupported,
                           "rclone does not support operations/check",
                           response.error().native_code));
        }
        return std::unexpected(response.error());
    }

    return parse_physical_hash_batch_response_json(*response, request);
}

struct JobBatchItemStatus {
    int status{200};
    bool has_error{false};
    std::string error_message;

    bool is_not_found() const noexcept {
        return status == 404 || (has_error && error_message.find("not found") !=
                                                  std::string::npos);
    }
};

std::expected<JobBatchItemStatus, Error>
parse_job_batch_item_status(const nlohmann::json& item,
                            std::string_view operation_name,
                            bool require_nonempty_error_with_status) {
    JobBatchItemStatus parsed;
    if (item.contains("status")) {
        auto parsed_status =
            parse_job_batch_status(item.at("status"), operation_name);
        if (!parsed_status) {
            return std::unexpected(parsed_status.error());
        }
        parsed.status = *parsed_status;
    }
    if (item.contains("error")) {
        if (!item.at("error").is_string()) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           require_nonempty_error_with_status
                               ? "invalid job/batch subcommand error"
                               : "invalid remove job/batch error result"));
        }
        parsed.has_error = true;
        parsed.error_message = item.at("error").get<std::string>();
        if (require_nonempty_error_with_status &&
            (parsed.error_message.empty() || !item.contains("status"))) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "invalid job/batch subcommand error"));
        }
    }
    return parsed;
}

ControlReadBatchResponse
parse_control_read_batch_response_json(const nlohmann::json& response,
                                       const ControlReadBatchRequest& request) {
    const auto expected_size =
        request.list_prefixes.size() + request.presence_identifiers.size();
    if (!response.is_object() || !response.contains("results") ||
        !response.at("results").is_array() ||
        response.at("results").size() != expected_size) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure, "invalid control job/batch response"));
    }

    const auto missing =
        [](const nlohmann::json& item) -> std::expected<bool, Error> {
        if (!item.is_object()) {
            return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                              "invalid job/batch result"));
        }
        const auto parsed = parse_job_batch_item_status(item, "control", true);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        if (parsed->has_error) {
            if (parsed->status == 404) {
                return true;
            }
            return std::unexpected(make_error(
                ErrorCode::ProtocolFailure,
                "job/batch subcommand failed; remote detail omitted"));
        }
        if (parsed->status < 200 || parsed->status >= 300) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "job/batch subcommand status indicates failure"));
        }
        return false;
    };

    ControlReadBatchResult result;
    result.listings.reserve(request.list_prefixes.size());
    result.presences.reserve(request.presence_identifiers.size());
    for (std::size_t index = 0; index < request.list_prefixes.size(); ++index) {
        const auto& item = response.at("results").at(index);
        auto absent = missing(item);
        if (!absent) {
            return std::unexpected(absent.error());
        }
        if (*absent) {
            if (item.contains("list") &&
                (!item.at("list").is_array() || !item.at("list").empty())) {
                return std::unexpected(
                    make_error(ErrorCode::ProtocolFailure,
                               "contradictory 404 job/batch result"));
            }
            result.listings.emplace_back();
            continue;
        }
        auto listing =
            parse_list_response_json(item, request.list_prefixes[index]);
        if (!listing) {
            return std::unexpected(listing.error());
        }
        result.listings.push_back(std::move(*listing));
    }

    for (std::size_t offset = 0; offset < request.presence_identifiers.size();
         ++offset) {
        const auto& item =
            response.at("results").at(request.list_prefixes.size() + offset);
        const auto& expected_identifier = request.presence_identifiers[offset];

        if (item.contains("input") && item.at("input").is_object() &&
            item.at("input").contains("remote") &&
            item.at("input").at("remote").is_string() &&
            item.at("input").at("remote").get_ref<const std::string&>() !=
                expected_identifier) {
            return std::unexpected(make_error(
                ErrorCode::ProtocolFailure,
                "job/batch result input does not match expected position"));
        }

        auto absent = missing(item);
        if (!absent) {
            return std::unexpected(absent.error());
        }
        if (*absent) {
            if (item.contains("item") && !item.at("item").is_null()) {
                return std::unexpected(
                    make_error(ErrorCode::ProtocolFailure,
                               "contradictory 404 job/batch result"));
            }
            result.presences.push_back(Presence::Absent);
            continue;
        }
        if (!item.contains("item")) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "invalid operations/stat response in job/batch"));
        }
        auto presence =
            parse_stat_presence(item.at("item"),
                                "invalid operations/stat response in job/batch",
                                "remote control object is a directory");
        if (!presence) {
            return std::unexpected(presence.error());
        }
        result.presences.push_back(*presence);
    }
    return result;
}

ControlReadBatchResponse
execute_single_control_read_batch(State& state,
                                  const ControlReadBatchRequest& request,
                                  std::size_t concurrency) {
    nlohmann::json inputs = nlohmann::json::array();
    for (const auto& prefix : request.list_prefixes) {
        inputs.push_back(nlohmann::json{{"_path", "operations/list"},
                                        {"fs", rooted_remote_fs(state)},
                                        {"remote", prefix},
                                        {"opt", stat_opt(true, false)}});
    }
    for (const auto& identifier : request.presence_identifiers) {
        inputs.push_back(nlohmann::json{{"_path", "operations/stat"},
                                        {"fs", rooted_remote_fs(state)},
                                        {"remote", identifier},
                                        {"opt", stat_opt(true)}});
    }

    const auto response = run_job_batch(state,
                                        inputs,
                                        concurrency,
                                        maximum_list_response_size,
                                        control_read_deadline,
                                        true);
    if (!response) {
        return std::unexpected(response.error());
    }
    return parse_control_read_batch_response_json(*response, request);
}

ControlReadBatchResponse
rclone_control_read_batch(void* context,
                          const ControlReadBatchRequest& request) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }

    constexpr std::size_t control_presence_concurrency = 8;
    constexpr std::size_t max_presence_batch_chunk_size = 128;

    // Admission depends on the ordering LIST writers -> STAT barrier;
    // rclone executes inputs sequentially when concurrency <= 1.
    if (!request.list_prefixes.empty() &&
        request.presence_identifiers.size() <= max_presence_batch_chunk_size) {
        return execute_single_control_read_batch(**state, request, 1);
    }

    if (request.list_prefixes.empty() && request.presence_identifiers.empty()) {
        return ControlReadBatchResult{};
    }

    ControlReadBatchResult aggregated;
    if (!request.list_prefixes.empty()) {
        ControlReadBatchRequest list_req;
        list_req.list_prefixes = request.list_prefixes;
        auto list_res = execute_single_control_read_batch(**state, list_req, 1);
        if (!list_res) {
            return std::unexpected(list_res.error());
        }
        aggregated.listings = std::move(list_res->listings);
    }
    aggregated.presences.reserve(request.presence_identifiers.size());

    for (std::size_t offset = 0; offset < request.presence_identifiers.size();
         offset += max_presence_batch_chunk_size) {
        const auto count =
            std::min(max_presence_batch_chunk_size,
                     request.presence_identifiers.size() - offset);
        ControlReadBatchRequest chunk_req;
        chunk_req.presence_identifiers.assign(
            request.presence_identifiers.begin() +
                static_cast<std::ptrdiff_t>(offset),
            request.presence_identifiers.begin() +
                static_cast<std::ptrdiff_t>(offset + count));

        auto chunk_res = execute_single_control_read_batch(
            **state, chunk_req, control_presence_concurrency);
        if (!chunk_res) {
            return std::unexpected(chunk_res.error());
        }
        aggregated.presences.insert(aggregated.presences.end(),
                                    chunk_res->presences.begin(),
                                    chunk_res->presences.end());
    }

    return aggregated;
}

RemovalResult rclone_remove(void* context, std::string_view identifier) {
    auto state = require_ready(context, identifier);
    if (!state) {
        return std::unexpected(state.error());
    }

    const auto deleted =
        request_json(**state,
                     "operations/deletefile",
                     nlohmann::json{{"fs", rooted_remote_fs(**state)},
                                    {"remote", std::string{identifier}}},
                     maximum_response_size,
                     remove_timeout);
    if (!deleted) {
        if (not_found(deleted.error())) {
            return Removal::AlreadyAbsent;
        }
        return std::unexpected(deleted.error());
    }
    return Removal::Removed;
}

RemoveBatchResult rclone_remove_batch(void* context, const RemoveBatch& batch) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (batch.items.empty()) {
        return RemoveBatchReport{};
    }
    if (batch.concurrency == 0) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "remove batch concurrency must be positive"));
    }

    nlohmann::json inputs = nlohmann::json::array();
    std::unordered_map<std::string, std::size_t> remote_to_index;
    for (std::size_t index = 0; index < batch.items.size(); ++index) {
        const auto& identifier = batch.items[index].identifier;
        if (!valid_identifier(identifier) ||
            !remote_to_index.emplace(std::string{identifier}, index).second) {
            return std::unexpected(invalid_identifier_error());
        }
        inputs.push_back(nlohmann::json{
            {"_path", "operations/deletefile"},
            {"fs", rooted_remote_fs(**state)},
            {"remote", identifier},
        });
    }

    const auto response = run_job_batch(**state,
                                        inputs,
                                        batch.concurrency,
                                        maximum_response_size,
                                        transfer_timeout,
                                        false);
    if (!response) {
        return std::unexpected(response.error());
    }

    if (!response->is_object() || response->contains("error") ||
        !response->contains("results") || !response->at("results").is_array() ||
        response->at("results").size() != batch.items.size()) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "invalid or incomplete remove job/batch response"));
    }

    RemoveBatchReport report;
    report.items.resize(batch.items.size());
    for (std::size_t index = 0; index < batch.items.size(); ++index) {
        report.items[index].identifier = batch.items[index].identifier;
    }

    std::vector<bool> matched(batch.items.size(), false);
    for (std::size_t index = 0; index < batch.items.size(); ++index) {
        const auto& result = response->at("results").at(index);
        if (!result.is_object()) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "invalid remove job/batch subresult"));
        }
        if (result.contains("path") &&
            (!result.at("path").is_string() ||
             result.at("path") != "operations/deletefile")) {
            return std::unexpected(make_error(
                ErrorCode::ProtocolFailure,
                "remove job/batch result path does not match input"));
        }

        std::size_t target_index = index;
        if (result.contains("input")) {
            const auto& input_echo = result.at("input");
            if (!input_echo.is_object() || !input_echo.contains("remote") ||
                !input_echo.at("remote").is_string()) {
                return std::unexpected(make_error(
                    ErrorCode::ProtocolFailure,
                    "remove job/batch result input does not match request"));
            }
            const auto remote_echo = input_echo.at("remote").get<std::string>();
            auto it = remote_to_index.find(remote_echo);
            if (it == remote_to_index.end()) {
                return std::unexpected(make_error(
                    ErrorCode::ProtocolFailure,
                    "unknown identifier in remove job/batch result"));
            }
            target_index = it->second;
        }

        if (matched[target_index]) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "duplicate item in remove job/batch response"));
        }
        matched[target_index] = true;

        const auto parsed =
            parse_job_batch_item_status(result, "remove", false);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        if (parsed->is_not_found()) {
            report.items[target_index].result = Removal::AlreadyAbsent;
        } else if (parsed->status >= 200 && parsed->status < 300 &&
                   !parsed->has_error) {
            report.items[target_index].result = Removal::Removed;
        } else {
            report.items[target_index].result = std::unexpected(make_error(
                ErrorCode::ProtocolFailure,
                parsed->error_message.empty() ? "remote remove failed"
                                              : parsed->error_message,
                parsed->status));
        }
    }

    for (bool m : matched) {
        if (!m) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "missing item in remove job/batch response"));
        }
    }

    return report;
}

template <typename Fn>
auto parse_json_response(std::string_view response_body,
                         std::string_view error_message,
                         Fn fn) {
    try {
        return fn(nlohmann::json::parse(response_body));
    } catch (const std::exception&) {
        return decltype(fn(nlohmann::json{})){std::unexpected(make_error(
            ErrorCode::ProtocolFailure, std::string{error_message}))};
    }
}

} // namespace

ControlReadBatchResponse
parse_control_read_batch_response(std::string_view response_body,
                                  const ControlReadBatchRequest& request) {
    return parse_json_response(
        response_body,
        "invalid control job/batch response",
        [&](const auto& j) {
            return parse_control_read_batch_response_json(j, request);
        });
}

PhysicalHashBatchResult
parse_physical_hash_batch_response(std::string_view response_body,
                                   const PhysicalHashBatchRequest& request) {
    return parse_json_response(
        response_body, "invalid operations/check response", [&](const auto& j) {
            return parse_physical_hash_batch_response_json(j, request);
        });
}

ListingResult parse_list_response(std::string_view response_body) {
    return parse_json_response(
        response_body, "invalid operations/list response", [](const auto& j) {
            return parse_list_response_json(j);
        });
}

StorageOperations make_storage_operations() noexcept {
    return StorageOperations{
        .initialize = rclone_initialize,
        .put = rclone_put,
        .put_batch = rclone_put_batch,
        .get = rclone_get,
        .get_batch = rclone_get_batch,
        .presence = rclone_presence,
        .list = rclone_list,
        .list_prefix = rclone_list_prefix,
        .physical_hash = rclone_physical_hash,
        .physical_hash_batch = rclone_physical_hash_batch,
        .control_read_batch = rclone_control_read_batch,
        .remove = rclone_remove,
        .remove_batch = rclone_remove_batch,
        .physical_hash_batch_min_objects = 6,
    };
}

} // namespace kasumi::transport::rclone_detail
