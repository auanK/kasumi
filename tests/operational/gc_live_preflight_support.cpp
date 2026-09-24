#include "gc_live_preflight_support.hpp"

#include "../../src/transport/rclone/detail.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <set>
#include <utility>

namespace kasumi::operational::gc_live_preflight {
namespace transport = kasumi::transport;
namespace rclone_detail = kasumi::transport::rclone_detail;

namespace {

constexpr std::string_view owner_identifier = "owner.marker";
constexpr std::string_view missing_directory_signature =
    "error in ListJSON: directory not found";

bool valid_parent(const remote_copy_smoke::RemoteParent& parent) {
    const auto parsed =
        remote_copy_smoke::parse_remote_parent(parent.location);
    return parsed && parsed->location == parent.location &&
           parsed->remote_name == parent.remote_name &&
           parsed->directory == parent.directory;
}

transport::Error error(transport::ErrorCode code, std::string message) {
    return transport::Error{.code = code, .message = std::move(message)};
}

std::string join_remote_path(std::string_view root,
                             std::string_view suffix) {
    while (root.ends_with('/')) {
        root.remove_suffix(1);
    }
    while (suffix.starts_with('/')) {
        suffix.remove_prefix(1);
    }
    if (root.empty()) {
        return std::string{suffix};
    }
    if (suffix.empty()) {
        return std::string{root};
    }
    return std::string{root} + "/" + std::string{suffix};
}

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

ListingObservation observe_listing(transport::ListingResult listing,
                                   const rclone_detail::State* state = nullptr) {
    if (listing) {
        return ListingObservation{.result = "SUCCESS",
                                  .entry_count = listing->size()};
    }
    auto message = listing.error().message;
    if (state != nullptr) {
        message = remote_copy_smoke::sanitize_rc_message(
            std::move(message), state->username, state->password);
    }
    return ListingObservation{
        .result = "FAILED",
        .error_category = listing.error().code,
        .native_code = listing.error().native_code,
        .error_message = std::move(message),
    };
}

RcDiagnostic failed_rc(std::string fs,
                       std::string remote,
                       transport::ErrorCode code,
                       std::string message,
                       std::optional<int> native_status = std::nullopt) {
    return RcDiagnostic{
        .request_fs = std::move(fs),
        .request_remote = std::move(remote),
        .result = "FAILED",
        .native_status = native_status,
        .error_category = code,
        .error_message = std::move(message),
    };
}

bool matches_parent_storage(
    transport::Transport& storage,
    const remote_copy_smoke::RemoteParent& parent,
    rclone_detail::State*& state) {
    if (!valid_parent(parent)) {
        return false;
    }
    const auto operations = rclone_detail::make_storage_operations();
    if (storage.storage.list_prefix != operations.list_prefix ||
        storage.storage.list != operations.list) {
        return false;
    }
    state = static_cast<rclone_detail::State*>(storage.state.get());
    return state != nullptr && state->ready &&
           state->configuration.remote_name == parent.remote_name &&
           state->configuration.remote_root == parent.directory;
}

bool matches_child_storage(const ChildStorage& child) {
    if (!valid_parent(child.parent) || !valid_child(child.child)) {
        return false;
    }
    const auto operations = rclone_detail::make_storage_operations();
    if (child.storage.storage.initialize != operations.initialize) {
        // Non-rclone transports are used only by the offline fake tests.
        return true;
    }
    const auto* state =
        static_cast<const rclone_detail::State*>(child.storage.state.get());
    return state != nullptr && state->ready &&
           state->configuration.remote_name == child.parent.remote_name &&
           state->configuration.remote_root ==
               join_remote_path(child.parent.directory, child.child);
}

std::optional<std::string> read_text(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }
    std::string contents{std::istreambuf_iterator<char>{input}, {}};
    if (input.bad()) {
        return std::nullopt;
    }
    return contents;
}

CleanupResult refused(std::string detail,
                      std::optional<transport::ErrorCode> code = std::nullopt) {
    return CleanupResult{.result = "refused",
                         .detail = std::move(detail),
                         .error_category = code};
}

nlohmann::json error_json(
    const std::optional<transport::ErrorCode>& code) {
    return code ? nlohmann::json(std::string{transport::error_code_name(*code)})
                : nlohmann::json(nullptr);
}

bool strict_missing_directory(const RcDiagnostic& diagnostic) noexcept {
    return diagnostic.result == "FAILED" &&
           diagnostic.endpoint == "operations/list" &&
           diagnostic.native_status == 404 &&
           diagnostic.error_category == transport::ErrorCode::ProtocolFailure &&
           diagnostic.error_message.ends_with(missing_directory_signature);
}

} // namespace

std::expected<std::string, std::string>
child_namespace(std::string_view random_hex) {
    constexpr std::string_view prefix = "kasumi-gc-live-";
    if (random_hex.size() != 32 ||
        !std::all_of(random_hex.begin(), random_hex.end(), [](char value) {
            return (value >= '0' && value <= '9') ||
                   (value >= 'a' && value <= 'f');
        })) {
        return std::unexpected("namespace nonce must be 128-bit lowercase hex");
    }
    return std::string{prefix} + std::string{random_hex};
}

bool valid_child(std::string_view child) noexcept {
    constexpr std::string_view prefix = "kasumi-gc-live-";
    constexpr std::string_view benchmark_prefix = "kasumi-gc-benchmark-";
    std::string_view active_prefix;
    if (child.starts_with(prefix)) {
        active_prefix = prefix;
    } else if (child.starts_with(benchmark_prefix)) {
        active_prefix = benchmark_prefix;
    } else {
        return false;
    }
    return child.size() == active_prefix.size() + 32 &&
           std::all_of(child.begin() + static_cast<std::ptrdiff_t>(active_prefix.size()),
                       child.end(),
                       [](char value) {
                           return (value >= '0' && value <= '9') ||
                                  (value >= 'a' && value <= 'f');
                       });
}

std::expected<std::string, std::string> child_location(
    const remote_copy_smoke::RemoteParent& parent,
    std::string_view child) {
    if (!valid_parent(parent) || !valid_child(child)) {
        return std::unexpected("invalid generated GC-live child namespace");
    }
    return parent.location + "/" + std::string{child};
}

PreInitializeObservation observe_pre_initialize(
    transport::Transport& parent_storage,
    const remote_copy_smoke::RemoteParent& parent,
    std::string_view child,
    std::chrono::milliseconds diagnostic_deadline) {
    if (!valid_child(child)) {
        const auto failure = error(transport::ErrorCode::InvalidIdentifier,
                                   "invalid generated GC-live child namespace");
        return {.transport = observe_listing(
                    transport::ListingResult{std::unexpected(failure)}),
                .raw_rc = failed_rc({}, {}, failure.code, failure.message)};
    }

    rclone_detail::State* state = nullptr;
    if (!matches_parent_storage(parent_storage, parent, state)) {
        const auto failure = error(transport::ErrorCode::InvalidContext,
                                   "parent Transport does not match validated rclone parent");
        return {.transport = observe_listing(
                    transport::ListingResult{std::unexpected(failure)}),
                .raw_rc = failed_rc({}, {}, failure.code, failure.message)};
    }

    const auto fs = state->configuration.remote_name + ":";
    const auto remote = join_remote_path(state->configuration.remote_root, child);
    RcDiagnostic raw{
        .request_fs = fs,
        .request_remote = remote,
    };
    const nlohmann::json request{
        {"fs", fs},
        {"remote", remote},
        {"opt", {{"recurse", false},
                 {"filesOnly", true},
                 {"noModTime", true},
                 {"noMimeType", true}}},
    };
    const auto response = rclone_detail::post_rc_read_only(
        *state,
        raw.endpoint,
        request.dump(),
        64U * 1024U * 1024U,
        diagnostic_deadline);
    if (!response) {
        raw.error_category = response.error().code;
        if (response.error().code == transport::ErrorCode::ProtocolFailure ||
            response.error().code == transport::ErrorCode::PermissionDenied) {
            raw.native_status = response.error().native_code;
        }
        raw.error_message = remote_copy_smoke::sanitize_rc_message(
            response.error().message, state->username, state->password);
    } else {
        auto listing = rclone_detail::parse_list_response(*response);
        if (listing) {
            raw.result = "SUCCESS";
            raw.entry_count = listing->size();
        } else {
            raw.error_category = listing.error().code;
            raw.error_message = remote_copy_smoke::sanitize_rc_message(
                listing.error().message, state->username, state->password);
        }
    }

    auto transport_listing = transport::list(parent_storage, child);
    return {.transport = observe_listing(std::move(transport_listing), state),
            .raw_rc = std::move(raw)};
}

Classification classify_pre_initialize(
    const PreInitializeObservation& observation,
    const remote_copy_smoke::RemoteParent& parent,
    std::string_view child) {
    if (!valid_parent(parent) || !valid_child(child)) {
        return {.disposition = ChildDisposition::Refused,
                .reason = "validated parent or generated child namespace is invalid"};
    }
    const auto expected_fs = parent.remote_name + ":";
    const auto expected_remote = join_remote_path(parent.directory, child);
    if (observation.raw_rc.endpoint != "operations/list" ||
        observation.raw_rc.request_fs != expected_fs ||
        observation.raw_rc.request_remote != expected_remote) {
        return {.disposition = ChildDisposition::Refused,
                .reason = "raw RC evidence does not match the exact child probe"};
    }
    if (observation.transport.result == "SUCCESS" &&
        observation.transport.entry_count > 0) {
        return {.disposition = ChildDisposition::Existing,
                .reason = "pre-initialize listing found child objects"};
    }
    if (observation.raw_rc.result == "SUCCESS" &&
        observation.raw_rc.entry_count.value_or(0) > 0) {
        return {.disposition = ChildDisposition::Existing,
                .reason = "raw RC listing found child objects"};
    }
    if (observation.transport.result == "SUCCESS") {
        return {.disposition = ChildDisposition::Refused,
                .reason = "empty pre-initialize listing cannot prove namespace absence"};
    }
    if (observation.transport.error_category !=
        transport::ErrorCode::StorageNotFound) {
        return {.disposition = ChildDisposition::Refused,
                .reason = "Transport did not report the child prefix as absent"};
    }
    if (strict_missing_directory(observation.raw_rc)) {
        return {.disposition = ChildDisposition::Unused,
                .reason = "Transport and strict operations/list missing-directory response agree"};
    }
    return {.disposition = ChildDisposition::Refused,
            .reason = "normalized StorageNotFound lacks strict RC absence evidence"};
}

std::expected<ChildStorage, transport::Error> open_child_storage(
    const remote_copy_smoke::RemoteParent& parent,
    std::string_view child) {
    const auto location =
        kasumi::operational::gc_live_preflight::child_location(parent, child);
    if (!location) {
        return std::unexpected(error(transport::ErrorCode::InvalidIdentifier,
                                     location.error()));
    }
    auto storage = transport::open_transport(*location);
    if (!storage) {
        return std::unexpected(storage.error());
    }
    return ChildStorage{.parent = parent,
                        .child = std::string{child},
                        .storage = std::move(*storage)};
}

transport::Result initialize_child(
    ChildStorage& child,
    const PreInitializeObservation& pre_initialize) {
    const auto classification = classify_pre_initialize(
        pre_initialize, child.parent, child.child);
    if (classification.disposition != ChildDisposition::Unused) {
        return std::unexpected(error(transport::ErrorCode::InvalidIdentifier,
                                     classification.reason));
    }
    if (!matches_child_storage(child)) {
        return std::unexpected(error(transport::ErrorCode::InvalidContext,
                                     "child Transport is not scoped to its generated namespace"));
    }
    return transport::initialize(child.storage);
}

PostInitializeObservation observe_post_initialize(ChildStorage& child) {
    if (!matches_child_storage(child)) {
        return {.transport = {.result = "FAILED",
                              .error_category = transport::ErrorCode::InvalidContext,
                              .error_message = "child Transport is not scoped to its generated namespace"}};
    }
    const auto* state = static_cast<const rclone_detail::State*>(
        child.storage.storage.initialize ==
                rclone_detail::make_storage_operations().initialize
            ? child.storage.state.get()
            : nullptr);
    return {.transport = observe_listing(transport::list(child.storage), state)};
}

PostInitializeDisposition classify_post_initialize(
    const PostInitializeObservation& observation) noexcept {
    return observation.transport.result == "SUCCESS" &&
                   observation.transport.entry_count == 0
               ? PostInitializeDisposition::Empty
               : PostInitializeDisposition::Refused;
}

transport::Result establish_ownership_marker(
    ChildStorage& child,
    const PostInitializeObservation& post_initialize,
    std::string_view owner_token,
    const std::filesystem::path& marker_source,
    const std::filesystem::path& marker_readback) {
    if (!matches_child_storage(child) ||
        classify_post_initialize(post_initialize) !=
            PostInitializeDisposition::Empty ||
        owner_token.empty()) {
        return std::unexpected(error(transport::ErrorCode::InvalidIdentifier,
                                     "ownership gates were not satisfied"));
    }
    std::error_code fs_error;
    const auto source_status = std::filesystem::symlink_status(marker_source,
                                                               fs_error);
    if (fs_error || std::filesystem::is_symlink(source_status) ||
        !std::filesystem::is_regular_file(source_status)) {
        return std::unexpected(error(transport::ErrorCode::InvalidContext,
                                     "owner marker source is not a regular file"));
    }
    const auto marker_bytes = read_text(marker_source);
    if (!marker_bytes || *marker_bytes != owner_token) {
        return std::unexpected(error(transport::ErrorCode::InvalidContext,
                                     "owner marker source does not match run token"));
    }
    fs_error.clear();
    const auto readback_status = std::filesystem::symlink_status(marker_readback,
                                                                 fs_error);
    if (!fs_error && std::filesystem::exists(readback_status)) {
        return std::unexpected(error(transport::ErrorCode::InvalidContext,
                                     "owner marker readback path already exists"));
    }
    if (fs_error != std::errc::no_such_file_or_directory && fs_error) {
        return std::unexpected(error(transport::ErrorCode::Io,
                                     fs_error.message()));
    }
    auto uploaded = transport::put(child.storage, marker_source, owner_identifier);
    if (!uploaded) {
        return uploaded;
    }
    auto downloaded = transport::get(child.storage, owner_identifier,
                                      marker_readback);
    if (!downloaded) {
        return downloaded;
    }
    const auto observed = read_text(marker_readback);
    if (!observed || *observed != owner_token) {
        return std::unexpected(error(transport::ErrorCode::ProtocolFailure,
                                     "owner marker readback did not match run token"));
    }
    return {};
}

CleanupResult cleanup_owned_child(
    ChildStorage& child,
    std::string_view owner_token,
    const std::vector<std::string>& object_identifiers,
    const std::filesystem::path& local_scratch) {
    std::error_code fs_error;
    const auto scratch_status =
        std::filesystem::symlink_status(local_scratch, fs_error);
    if (!matches_child_storage(child) || owner_token.empty() || fs_error ||
        std::filesystem::is_symlink(scratch_status) ||
        !std::filesystem::is_directory(scratch_status)) {
        return refused("cleanup scope or local scratch is invalid");
    }
    std::set<std::string> unique;
    for (const auto& identifier : object_identifiers) {
        if (!safe_relative_identifier(identifier) ||
            identifier == owner_identifier || !unique.insert(identifier).second) {
            return refused("cleanup target is duplicate or outside the child");
        }
    }
    const auto marker_path = local_scratch / "gc-live-owner-check.tmp";
    fs_error.clear();
    const auto marker_status =
        std::filesystem::symlink_status(marker_path, fs_error);
    if ((!fs_error && std::filesystem::exists(marker_status)) ||
        (fs_error && fs_error != std::errc::no_such_file_or_directory)) {
        return refused("ownership check path already exists");
    }
    auto marker_read = transport::get(child.storage, owner_identifier,
                                      marker_path);
    if (!marker_read) {
        return refused("could not verify cleanup ownership",
                       marker_read.error().code);
    }
    const auto observed = read_text(marker_path);
    fs_error.clear();
    if (!std::filesystem::remove(marker_path, fs_error) || fs_error) {
        return refused("could not remove local ownership check file");
    }
    if (!observed || *observed != owner_token) {
        return refused("ownership marker does not match this run");
    }

    std::vector<std::string> present;
    for (const auto& identifier : object_identifiers) {
        const auto state_result = transport::presence(child.storage, identifier);
        if (!state_result) {
            return refused("could not establish cleanup target state",
                           state_result.error().code);
        }
        if (*state_result == transport::Presence::Present) {
            present.push_back(identifier);
        }
    }

    CleanupResult result{.result = "removed"};
    for (const auto& identifier : present) {
        const auto removed = transport::remove(child.storage, identifier);
        if (!removed) {
            return CleanupResult{
                .result = "failed",
                .detail = "failed to remove an owned child object",
                .removed_objects = result.removed_objects,
                .error_category = removed.error().code,
            };
        }
        result.removed_objects +=
            *removed == transport::Removal::Removed ? 1U : 0U;
    }
    const auto marker_removed = transport::remove(child.storage, owner_identifier);
    if (!marker_removed) {
        return CleanupResult{
            .result = "failed",
            .detail = "failed to remove ownership marker",
            .removed_objects = result.removed_objects,
            .error_category = marker_removed.error().code,
        };
    }
    result.removed_objects +=
        *marker_removed == transport::Removal::Removed ? 1U : 0U;
    result.detail = "ownership marker readback matched the run token";
    return result;
}

std::string sanitize_rc_message(std::string message,
                                std::string_view username,
                                std::string_view password) {
    return remote_copy_smoke::sanitize_rc_message(std::move(message),
                                                   username,
                                                   password);
}

nlohmann::json to_json(const PreInitializeObservation& observation,
                       const Classification& classification) {
    const auto raw_error_message = observation.raw_rc.error_message.empty()
                                       ? nlohmann::json(nullptr)
                                       : nlohmann::json(
                                             observation.raw_rc.error_message);
    return nlohmann::json{
        {"phase", "PRE_INITIALIZE"},
        {"transport_result", observation.transport.result},
        {"transport_entry_count",
         observation.transport.result == "SUCCESS"
             ? nlohmann::json(observation.transport.entry_count)
             : nlohmann::json(nullptr)},
        {"transport_error_category",
         error_json(observation.transport.error_category)},
        {"transport_native_code",
         observation.transport.native_code
             ? nlohmann::json(*observation.transport.native_code)
             : nlohmann::json(nullptr)},
        {"transport_error_message",
         observation.transport.error_message.empty()
             ? nlohmann::json(nullptr)
             : nlohmann::json(observation.transport.error_message)},
        {"raw_rc_endpoint", observation.raw_rc.endpoint},
        {"raw_rc_request_fs", observation.raw_rc.request_fs},
        {"raw_rc_request_remote", observation.raw_rc.request_remote},
        {"raw_rc_probe_result", observation.raw_rc.result},
        {"raw_rc_entry_count",
         observation.raw_rc.entry_count
             ? nlohmann::json(*observation.raw_rc.entry_count)
             : nlohmann::json(nullptr)},
        {"raw_rc_native_status",
         observation.raw_rc.native_status
             ? nlohmann::json(*observation.raw_rc.native_status)
             : nlohmann::json(nullptr)},
        {"raw_rc_error_category",
         error_json(observation.raw_rc.error_category)},
        {"raw_rc_error_message_sanitized", raw_error_message},
        {"classification", classification.disposition == ChildDisposition::Unused
                               ? "UNUSED"
                               : classification.disposition == ChildDisposition::Existing
                                     ? "EXISTING"
                                     : "REFUSED"},
        {"reason", classification.reason},
    };
}

nlohmann::json to_json(const PostInitializeObservation& observation,
                       PostInitializeDisposition classification) {
    return nlohmann::json{
        {"phase", "POST_INITIALIZE"},
        {"transport_result", observation.transport.result},
        {"transport_entry_count",
         observation.transport.result == "SUCCESS"
             ? nlohmann::json(observation.transport.entry_count)
             : nlohmann::json(nullptr)},
        {"transport_error_category",
         error_json(observation.transport.error_category)},
        {"transport_native_code",
         observation.transport.native_code
             ? nlohmann::json(*observation.transport.native_code)
             : nlohmann::json(nullptr)},
        {"transport_error_message",
         observation.transport.error_message.empty()
             ? nlohmann::json(nullptr)
             : nlohmann::json(observation.transport.error_message)},
        {"classification", classification == PostInitializeDisposition::Empty
                               ? "EMPTY_READY"
                               : "REFUSED"},
        {"reason", classification == PostInitializeDisposition::Empty
                       ? "initialized child listing succeeded and is empty"
                       : "initialized child listing failed or is non-empty"},
    };
}

nlohmann::json to_json(const CleanupResult& cleanup) {
    return nlohmann::json{{"result", cleanup.result},
                          {"detail", cleanup.detail},
                          {"removed_objects", cleanup.removed_objects},
                          {"error_category", error_json(cleanup.error_category)}};
}

} // namespace kasumi::operational::gc_live_preflight
