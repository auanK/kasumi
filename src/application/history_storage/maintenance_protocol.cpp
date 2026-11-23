#include "application/history_storage/maintenance_protocol.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/machine.hpp"
#include "platform/path.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <ranges>
#include <span>
#include <thread>
#include <utility>

namespace kasumi::application::history_storage::maintenance_protocol {
namespace {

constexpr std::size_t maximum_marker_size = 512;
constexpr std::size_t TOKEN_HEX_SIZE = 32;

bool is_canonical_hex32(std::string_view value) noexcept {
    return value.size() == TOKEN_HEX_SIZE &&
           std::ranges::all_of(value, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

Error error(
    ErrorCode code,
    std::string detail,
    std::optional<std::string> identifier = std::nullopt,
    std::optional<BarrierRemovalStage> stage = std::nullopt,
    std::optional<BarrierRemovalMutationState> mutation_state = std::nullopt) {
    return Error{
        .code = code,
        .detail = std::move(detail),
        .identifier = std::move(identifier),
        .stage = stage,
        .mutation_state = mutation_state,
    };
}

Error transport_error(
    const transport::Error& source,
    std::optional<std::string> prefix_msg = std::nullopt,
    std::optional<std::string> identifier = std::nullopt,
    std::optional<BarrierRemovalStage> stage = std::nullopt,
    std::optional<BarrierRemovalMutationState> mutation_state = std::nullopt) {
    std::string detail =
        prefix_msg ? (*prefix_msg + ": " + transport::describe(source))
                   : transport::describe(source);
    auto result = error(ErrorCode::TransportFailure,
                        std::move(detail),
                        std::move(identifier),
                        stage,
                        mutation_state);
    result.transport_failure = source;
    return result;
}

Error history_error(const history_storage::Error& source) {
    ErrorCode code = ErrorCode::VerificationFailure;
    if (source.code == history_storage::ErrorCode::WorkspaceFailure) {
        code = ErrorCode::WorkspaceFailure;
    } else if (source.code == history_storage::ErrorCode::TransportFailure) {
        code = ErrorCode::TransportFailure;
    }
    return error(code, source.detail);
}

MarkerMetadata default_metadata() {
    const auto now_sec =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    return MarkerMetadata{
        .machine_name = platform::machine::host_name(),
        .pid = platform::machine::current_process_id(),
        .started_at_unix = static_cast<std::int64_t>(now_sec),
    };
}

std::vector<std::uint8_t>
payload(std::string_view kind,
        std::string_view token,
        const std::optional<MarkerMetadata>& metadata = std::nullopt) {
    std::string value;
    value.reserve(13 + kind.size() + 1 + token.size() + 96);
    value.append("kasumi-gc-v1:");
    value.append(kind);
    value.push_back(':');
    value.append(token);
    if (metadata.has_value()) {
        const auto sanitized_machine =
            platform::machine::sanitize_machine_name(metadata->machine_name);
        value.append("\nstarted_at=");
        value.append(std::to_string(metadata->started_at_unix));
        value.append("\npid=");
        value.append(std::to_string(metadata->pid));
        value.append("\nmachine=");
        value.append(sanitized_machine);
    }
    return {value.begin(), value.end()};
}

enum class MarkerParseError {
    Ok,
    InvalidPrefix,
    InvalidToken,
    TokenMismatch,
    InvalidMetadata,
};

MarkerParseError
parse_marker_payload_impl(std::span<const std::uint8_t> bytes,
                          std::string_view expected_kind,
                          std::optional<std::string_view> expected_token,
                          std::string* parsed_token_out,
                          std::optional<MarkerMetadata>* metadata_out) {
    const std::string_view text{reinterpret_cast<const char*>(bytes.data()),
                                bytes.size()};
    if (text.find('\r') != std::string_view::npos) {
        return MarkerParseError::InvalidMetadata;
    }
    const auto nl = text.find('\n');
    const auto header =
        nl == std::string_view::npos ? text : text.substr(0, nl);
    const std::string prefix =
        "kasumi-gc-v1:" + std::string{expected_kind} + ":";
    if (!header.starts_with(prefix)) {
        return MarkerParseError::InvalidPrefix;
    }
    const auto token = header.substr(prefix.size());
    if (!is_canonical_hex32(token)) {
        return MarkerParseError::InvalidToken;
    }
    if (expected_token.has_value() && token != *expected_token) {
        return MarkerParseError::TokenMismatch;
    }
    if (parsed_token_out != nullptr) {
        *parsed_token_out = std::string{token};
    }
    if (nl == std::string_view::npos) {
        if (metadata_out != nullptr) {
            *metadata_out = std::nullopt;
        }
        return MarkerParseError::Ok;
    }

    auto rest = text.substr(nl + 1);
    if (rest.empty()) {
        return MarkerParseError::InvalidMetadata;
    }
    MarkerMetadata meta;
    bool seen_started = false;
    bool seen_pid = false;
    bool seen_machine = false;
    while (!rest.empty()) {
        const auto next_nl = rest.find('\n');
        const auto line =
            next_nl == std::string_view::npos ? rest : rest.substr(0, next_nl);
        if (line.empty()) {
            return MarkerParseError::InvalidMetadata;
        }
        if (line.starts_with("started_at=")) {
            if (seen_started) {
                return MarkerParseError::InvalidMetadata;
            }
            const auto val = line.substr(11);
            std::int64_t parsed = 0;
            const auto [ptr, ec] =
                std::from_chars(val.data(), val.data() + val.size(), parsed);
            if (ec != std::errc{} || ptr != val.data() + val.size()) {
                return MarkerParseError::InvalidMetadata;
            }
            meta.started_at_unix = parsed;
            seen_started = true;
        } else if (line.starts_with("pid=")) {
            if (seen_pid) {
                return MarkerParseError::InvalidMetadata;
            }
            const auto val = line.substr(4);
            std::uint64_t parsed = 0;
            const auto [ptr, ec] =
                std::from_chars(val.data(), val.data() + val.size(), parsed);
            if (ec != std::errc{} || ptr != val.data() + val.size()) {
                return MarkerParseError::InvalidMetadata;
            }
            meta.pid = parsed;
            seen_pid = true;
        } else if (line.starts_with("machine=")) {
            if (seen_machine) {
                return MarkerParseError::InvalidMetadata;
            }
            const auto val = line.substr(8);
            if (val.empty()) {
                return MarkerParseError::InvalidMetadata;
            }
            meta.machine_name = platform::machine::sanitize_machine_name(val);
            seen_machine = true;
        } else {
            return MarkerParseError::InvalidMetadata;
        }
        if (next_nl == std::string_view::npos) {
            break;
        }
        rest = rest.substr(next_nl + 1);
        if (rest.empty()) {
            return MarkerParseError::InvalidMetadata;
        }
    }
    if (!seen_started || !seen_pid || !seen_machine) {
        return MarkerParseError::InvalidMetadata;
    }
    if (metadata_out != nullptr) {
        *metadata_out = std::move(meta);
    }
    return MarkerParseError::Ok;
}

std::expected<std::vector<std::string>, Error>
list_children(transport::Transport& storage, std::string_view prefix) {
    auto listed = detail::list_transport_identifiers(storage, prefix);
    if (!listed) {
        return std::unexpected(transport_error(listed.error()));
    }
    return std::move(*listed);
}

struct ControlReadSnapshot {
    std::vector<std::string> writers;
    std::vector<std::string> barrier_tokens;
    transport::Presence legacy_barrier = transport::Presence::Absent;
};

std::expected<ControlReadSnapshot, Error>
read_control_snapshot(transport::Transport& storage,
                      const RemoteLayout& layout,
                      bool include_writers) {
    const auto writers_dir = detail::trim_trailing_slash(layout.writers_prefix);
    const auto barriers_dir =
        detail::trim_trailing_slash(layout.barriers_prefix);
    transport::ControlReadBatchRequest req;
    if (include_writers) {
        req.list_prefixes.push_back(std::string{writers_dir});
    }
    req.list_prefixes.push_back(std::string{barriers_dir});
    req.presence_identifiers.push_back(layout.barrier_identifier);

    auto batch = transport::control_read_batch(storage, req);
    if (batch) {
        const std::size_t expected_listings = include_writers ? 2U : 1U;
        if (batch->listings.size() != expected_listings ||
            batch->presences.size() != 1U) {
            return std::unexpected(
                error(ErrorCode::InvalidControlObject,
                      "incomplete admission batch response"));
        }
        ControlReadSnapshot snapshot;
        if (include_writers) {
            snapshot.writers = std::move(batch->listings[0]);
            snapshot.barrier_tokens = std::move(batch->listings[1]);
        } else {
            snapshot.barrier_tokens = std::move(batch->listings[0]);
        }
        snapshot.legacy_barrier = batch->presences[0];
        return snapshot;
    }
    if (batch.error().code != transport::ErrorCode::Unsupported) {
        return std::unexpected(transport_error(batch.error()));
    }

    ControlReadSnapshot snapshot;
    if (include_writers) {
        auto writers = list_children(storage, writers_dir);
        if (!writers) {
            return std::unexpected(writers.error());
        }
        snapshot.writers = std::move(*writers);
    }
    auto barriers = list_children(storage, barriers_dir);
    if (!barriers) {
        return std::unexpected(barriers.error());
    }
    snapshot.barrier_tokens = std::move(*barriers);
    auto legacy = transport::presence(storage, layout.barrier_identifier);
    if (!legacy) {
        return std::unexpected(transport_error(legacy.error()));
    }
    snapshot.legacy_barrier = *legacy;
    return snapshot;
}

bool any_barrier_present(const ControlReadSnapshot& snapshot) noexcept {
    return snapshot.legacy_barrier == transport::Presence::Present ||
           !snapshot.barrier_tokens.empty();
}

std::expected<bool, Error>
verify_remote_payload(transport::Transport& storage,
                      std::string_view identifier,
                      std::span<const std::uint8_t> expected,
                      const std::filesystem::path& workspace_root,
                      std::string_view expected_hash) {
    auto remote_hash = transport::physical_hash(storage, identifier, "sha256");
    if (remote_hash) {
        if (!history::valid_commit_id(*remote_hash)) {
            return std::unexpected(error(ErrorCode::VerificationFailure,
                                         "invalid remote barrier SHA-256"));
        }
        if (!history::valid_commit_id(expected_hash)) {
            return std::unexpected(error(ErrorCode::VerificationFailure,
                                         "invalid expected barrier SHA-256"));
        }
        return *remote_hash == expected_hash;
    }
    if (remote_hash.error().code != transport::ErrorCode::Unsupported) {
        return std::unexpected(transport_error(remote_hash.error()));
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(history_error(temporary.error()));
    }
    const auto copy = (*temporary)->workspace.root / "marker.copy";
    auto downloaded = transport::get(storage, identifier, copy);
    if (!downloaded) {
        return std::unexpected(transport_error(downloaded.error()));
    }
    auto observed = detail::read_file(copy, maximum_marker_size);
    if (!observed) {
        return std::unexpected(history_error(observed.error()));
    }
    return std::ranges::equal(*observed, expected);
}

std::expected<std::string, Error>
put_verified(transport::Transport& storage,
             std::string_view identifier,
             std::span<const std::uint8_t> bytes,
             const std::filesystem::path& workspace_root) {
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(history_error(temporary.error()));
    }
    const auto source = (*temporary)->workspace.root / "marker.source";
    const auto copy = (*temporary)->workspace.root / "marker.copy";
    if (auto written = detail::write_file(source, bytes); !written) {
        return std::unexpected(history_error(written.error()));
    }
    auto local_hash = crypto::physical::hash_file(source, "sha256");
    if (!local_hash) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, local_hash.error()));
    }
    auto sent = transport::put(storage, source, identifier);
    if (!sent) {
        return std::unexpected(transport_error(sent.error()));
    }
    auto remote_hash = transport::physical_hash(storage, identifier, "sha256");
    if (remote_hash) {
        if (*remote_hash != *local_hash) {
            return std::unexpected(
                error(ErrorCode::VerificationFailure,
                      "remote physical hash does not match published marker"));
        }
        return *local_hash;
    }
    if (remote_hash.error().code != transport::ErrorCode::Unsupported) {
        return std::unexpected(transport_error(remote_hash.error()));
    }
    if (auto downloaded = detail::download(storage, identifier, copy);
        !downloaded) {
        return std::unexpected(history_error(downloaded.error()));
    }
    auto observed = detail::read_file(copy, maximum_marker_size);
    if (!observed) {
        return std::unexpected(history_error(observed.error()));
    }
    if (!std::ranges::equal(*observed, bytes)) {
        return std::unexpected(
            error(ErrorCode::VerificationFailure,
                  "remote marker does not match published marker"));
    }
    return *local_hash;
}

bool contains_name(const std::vector<std::string>& names,
                   std::string_view name) {
    return std::ranges::find(names, name) != names.end();
}

std::expected<bool, Error>
registration_matches(transport::Transport& storage,
                     const RegistrationState& registration) {
    auto result = verify_remote_payload(storage,
                                        registration.identifier,
                                        registration.payload,
                                        registration.workspace_root,
                                        registration.expected_physical_sha256);
    if (!result && result.error().transport_failure &&
        result.error().transport_failure->code ==
            transport::ErrorCode::ObjectNotFound) {
        return false;
    }
    return result;
}

std::expected<void, Error>
verify_barrier_exclusivity_impl(const RegistrationState& registration,
                                const RemoteLayout& layout,
                                bool fail_missing_as_unsafe) {
    if (!registration_active(registration) ||
        !valid_barrier_identifier(layout, registration.identifier) ||
        !is_canonical_hex32(registration.token)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid barrier registration"));
    }
    auto snapshot = read_control_snapshot(*registration.storage, layout, true);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    if (snapshot->legacy_barrier == transport::Presence::Present) {
        return std::unexpected(
            error(ErrorCode::Blocked, "legacy maintenance barrier is active"));
    }
    if (!snapshot->writers.empty()) {
        return std::unexpected(
            error(ErrorCode::Blocked,
                  "active remote writers detected during collection"));
    }
    bool found_ours = false;
    for (const auto& entry : snapshot->barrier_tokens) {
        if (entry == registration.token) {
            found_ours = true;
        } else {
            return std::unexpected(
                error(ErrorCode::Blocked,
                      "competing maintenance barrier detected on destination"));
        }
    }
    if (!found_ours) {
        if (fail_missing_as_unsafe) {
            return std::unexpected(
                error(ErrorCode::BackendUnsafe,
                      "backend did not make barrier visible in listing"));
        }
        return std::unexpected(error(
            ErrorCode::Blocked, "barrier ownership lost during collection"));
    }
    return verify_registration(registration);
}

} // namespace

bool registration_active(const RegistrationState& registration) noexcept {
    return registration.storage != nullptr && !registration.identifier.empty();
}

std::expected<void, Error>
verify_registration(const RegistrationState& registration) {
    if (!registration_active(registration)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "remote registration is inactive"));
    }
    auto matches = registration_matches(*registration.storage, registration);
    if (!matches) {
        return std::unexpected(matches.error());
    }
    if (!*matches) {
        return std::unexpected(error(
            ErrorCode::Blocked, "barrier ownership changed during collection"));
    }
    return {};
}

std::expected<void, Error>
verify_writer_admission(const RegistrationState& registration,
                        const RemoteLayout& layout) {
    if (!registration_active(registration) ||
        !valid_writer_identifier(layout, registration.identifier)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid writer registration"));
    }
    auto owned = verify_registration(registration);
    if (!owned) {
        return std::unexpected(owned.error());
    }
    auto snapshot = read_control_snapshot(*registration.storage, layout, false);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    if (any_barrier_present(*snapshot)) {
        return std::unexpected(
            error(ErrorCode::Blocked, "GC active on destination"));
    }
    return {};
}

std::expected<void, Error>
verify_barrier_exclusivity(const RegistrationState& registration,
                           const RemoteLayout& layout) {
    return verify_barrier_exclusivity_impl(registration, layout, false);
}

std::expected<void, Error>
release_registration(RegistrationState& registration) {
    if (!registration_active(registration)) {
        return {};
    }
    auto* storage = std::exchange(registration.storage, nullptr);
    if (registration.verify_owner) {
        auto matches = registration_matches(*storage, registration);
        if (!matches) {
            return std::unexpected(matches.error());
        }
        if (!*matches) {
            return {};
        }
    }
    auto removed = transport::remove(*storage, registration.identifier);
    if (!removed) {
        return std::unexpected(transport_error(removed.error()));
    }
    return {};
}

RegistrationResult
register_writer(transport::Transport& storage,
                const RemoteLayout& layout,
                const std::filesystem::path& workspace_root) {
    return register_writer(storage, layout, workspace_root, default_metadata());
}

RegistrationResult register_writer(transport::Transport& storage,
                                   const RemoteLayout& layout,
                                   const std::filesystem::path& workspace_root,
                                   const MarkerMetadata& metadata) {
    if (!transport::valid(storage) || workspace_root.empty()) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid writer context"));
    }
    auto token = platform::random::hex_id();
    if (!token) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, token.error()));
    }
    const auto name = *token;
    const auto identifier = layout.writers_prefix + name;
    auto bytes = payload("writer", *token, metadata);
    auto published = put_verified(storage, identifier, bytes, workspace_root);
    if (!published) {
        return std::unexpected(published.error());
    }
    RegistrationState registration{.storage = &storage,
                                   .workspace_root = workspace_root,
                                   .identifier = identifier,
                                   .token = name,
                                   .payload = std::move(bytes),
                                   .expected_physical_sha256 =
                                       std::move(*published),
                                   .verify_owner = false};
    const auto fail_releasing = [&](Error failure) {
        static_cast<void>(release_registration(registration));
        return std::unexpected(std::move(failure));
    };
    auto snapshot = read_control_snapshot(storage, layout, true);
    if (!snapshot) {
        return fail_releasing(snapshot.error());
    }
    if (!contains_name(snapshot->writers, name)) {
        return fail_releasing(
            error(ErrorCode::BackendUnsafe,
                  "backend did not make writer visible in listing"));
    }
    if (any_barrier_present(*snapshot)) {
        return fail_releasing(
            error(ErrorCode::Blocked, "GC active on destination"));
    }
    return registration;
}

RegistrationResult
establish_barrier(transport::Transport& storage,
                  const RemoteLayout& layout,
                  const std::filesystem::path& workspace_root) {
    return establish_barrier(storage, layout, workspace_root, BarrierOptions{});
}

RegistrationResult
establish_barrier(transport::Transport& storage,
                  const RemoteLayout& layout,
                  const std::filesystem::path& workspace_root,
                  const BarrierOptions& options) {
    if (!transport::valid(storage) || workspace_root.empty()) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid barrier context"));
    }
    auto pre_check = read_control_snapshot(storage, layout, true);
    if (!pre_check) {
        return std::unexpected(pre_check.error());
    }
    if (any_barrier_present(*pre_check)) {
        return std::unexpected(
            error(ErrorCode::Blocked,
                  "remote garbage collection barrier is already active"));
    }
    if (!pre_check->writers.empty()) {
        return std::unexpected(error(
            ErrorCode::Blocked,
            "active remote writers detected before establishing barrier"));
    }

    auto token = platform::random::hex_id();
    if (!token) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, token.error()));
    }
    const auto name = *token;
    const auto identifier = layout.barriers_prefix + name;
    const auto meta = options.metadata.value_or(default_metadata());
    auto bytes = payload("barrier", name, meta);
    auto published = put_verified(storage, identifier, bytes, workspace_root);
    if (!published) {
        return std::unexpected(published.error());
    }
    RegistrationState registration{.storage = &storage,
                                   .workspace_root = workspace_root,
                                   .identifier = identifier,
                                   .token = name,
                                   .payload = std::move(bytes),
                                   .expected_physical_sha256 =
                                       std::move(*published),
                                   .verify_owner = true};
    if (options.settle_delay > std::chrono::milliseconds::zero()) {
        std::this_thread::sleep_for(options.settle_delay);
    }
    auto exclusive =
        verify_barrier_exclusivity_impl(registration, layout, true);
    if (!exclusive) {
        static_cast<void>(release_registration(registration));
        return std::unexpected(exclusive.error());
    }
    return registration;
}

std::expected<std::vector<std::string>, Error>
active_writers(transport::Transport& storage, const RemoteLayout& layout) {
    const auto writers_dir = detail::trim_trailing_slash(layout.writers_prefix);
    auto listed = list_children(storage, writers_dir);
    if (!listed) {
        return std::unexpected(listed.error());
    }
    std::vector<std::string> result;
    for (const auto& name : *listed) {
        if (!is_canonical_hex32(name)) {
            return std::unexpected(error(ErrorCode::InvalidControlObject,
                                         "invalid writer marker: " + name));
        }
        result.push_back(layout.writers_prefix + name);
    }
    return result;
}

std::expected<std::vector<std::string>, Error>
active_barriers(transport::Transport& storage, const RemoteLayout& layout) {
    auto snapshot = read_control_snapshot(storage, layout, false);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    std::vector<std::string> result;
    if (snapshot->legacy_barrier == transport::Presence::Present) {
        result.push_back(layout.barrier_identifier);
    }
    for (const auto& name : snapshot->barrier_tokens) {
        if (!is_canonical_hex32(name)) {
            return std::unexpected(error(ErrorCode::InvalidControlObject,
                                         "invalid barrier marker: " + name));
        }
        result.push_back(layout.barriers_prefix + name);
    }
    return result;
}

std::optional<MarkerMetadata>
parse_marker_metadata(std::span<const std::uint8_t> bytes,
                      std::string_view expected_kind,
                      std::optional<std::string_view> expected_token) {
    std::optional<MarkerMetadata> metadata;
    if (parse_marker_payload_impl(
            bytes, expected_kind, expected_token, nullptr, &metadata) !=
        MarkerParseError::Ok) {
        return std::nullopt;
    }
    return metadata;
}

std::optional<MarkerMetadata>
read_marker_metadata(transport::Transport& storage,
                     std::string_view identifier,
                     std::string_view expected_kind,
                     std::optional<std::string_view> expected_token,
                     const std::filesystem::path& workspace_root) {
    if (!transport::valid(storage) || workspace_root.empty()) {
        return std::nullopt;
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::nullopt;
    }
    const auto copy = (*temporary)->workspace.root / "marker.meta";
    auto downloaded = transport::get(storage, identifier, copy);
    if (!downloaded) {
        return std::nullopt;
    }
    auto observed = detail::read_file(copy, maximum_marker_size);
    if (!observed) {
        return std::nullopt;
    }
    return parse_marker_metadata(*observed, expected_kind, expected_token);
}

std::expected<void, Error> remove_writer(transport::Transport& storage,
                                         const RemoteLayout& layout,
                                         std::string_view identifier) {
    if (!transport::valid(storage) ||
        !valid_writer_identifier(layout, identifier)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid writer marker identifier"));
    }

    auto present = transport::presence(storage, identifier);
    if (!present) {
        return std::unexpected(transport_error(present.error()));
    }
    if (*present != transport::Presence::Present) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "writer marker does not exist"));
    }

    auto writers = active_writers(storage, layout);
    if (!writers) {
        return std::unexpected(writers.error());
    }
    const auto matches = std::ranges::count(*writers, identifier);
    if (matches != 1) {
        return std::unexpected(
            error(ErrorCode::InvalidControlObject,
                  matches == 0 ? "writer marker is not listed"
                               : "writer marker listing is ambiguous"));
    }

    auto snapshot = read_control_snapshot(storage, layout, false);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    if (any_barrier_present(*snapshot)) {
        return std::unexpected(
            error(ErrorCode::Blocked,
                  "maintenance barrier is present; writer removal is blocked"));
    }

    auto removed = transport::remove(storage, identifier);
    if (!removed) {
        return std::unexpected(transport_error(removed.error()));
    }
    if (*removed != transport::Removal::Removed) {
        return std::unexpected(
            error(ErrorCode::VerificationFailure,
                  "writer marker disappeared before it could be removed"));
    }

    present = transport::presence(storage, identifier);
    if (!present) {
        return std::unexpected(transport_error(present.error()));
    }
    if (*present != transport::Presence::Absent) {
        return std::unexpected(error(ErrorCode::VerificationFailure,
                                     "writer marker remains after removal"));
    }
    writers = active_writers(storage, layout);
    if (!writers) {
        return std::unexpected(writers.error());
    }
    if (std::ranges::find(*writers, identifier) != writers->end()) {
        return std::unexpected(error(ErrorCode::VerificationFailure,
                                     "writer marker remains listed"));
    }
    return {};
}

std::expected<BarrierRemovalResult, Error>
remove_barrier(transport::Transport& storage,
               const RemoteLayout& layout,
               const std::filesystem::path& workspace_root,
               std::optional<std::string_view> target_barrier) {
    std::string active_identifier = layout.barrier_identifier;
    auto with_context = [&](BarrierRemovalStage stage,
                            Error err,
                            BarrierRemovalMutationState mut =
                                BarrierRemovalMutationState::NotAttempted) {
        err.identifier = active_identifier;
        err.stage = stage;
        err.mutation_state = mut;
        return std::unexpected(std::move(err));
    };
    auto fail = [&](BarrierRemovalStage stage,
                    ErrorCode code,
                    std::string msg,
                    BarrierRemovalMutationState mut =
                        BarrierRemovalMutationState::NotAttempted) {
        return std::unexpected(
            error(code, std::move(msg), active_identifier, stage, mut));
    };
    auto fail_tx = [&](BarrierRemovalStage stage,
                       const transport::Error& err,
                       std::string msg,
                       BarrierRemovalMutationState mut =
                           BarrierRemovalMutationState::NotAttempted) {
        return std::unexpected(transport_error(
            err, std::move(msg), active_identifier, stage, mut));
    };

    if (!transport::valid(storage) || workspace_root.empty()) {
        return fail(BarrierRemovalStage::CheckingPresence,
                    ErrorCode::InvalidInput,
                    "invalid barrier removal context");
    }

    auto legacy_present =
        transport::presence(storage, layout.barrier_identifier);
    if (!legacy_present) {
        return fail_tx(BarrierRemovalStage::CheckingPresence,
                       legacy_present.error(),
                       "could not check maintenance barrier presence");
    }
    const auto barriers_dir =
        detail::trim_trailing_slash(layout.barriers_prefix);
    auto multi_barriers = list_children(storage, barriers_dir);
    if (!multi_barriers) {
        return with_context(BarrierRemovalStage::CheckingPresence,
                            multi_barriers.error());
    }
    std::vector<std::string> present_barriers;
    if (*legacy_present == transport::Presence::Present) {
        present_barriers.push_back(layout.barrier_identifier);
    }
    for (const auto& name : *multi_barriers) {
        if (!is_canonical_hex32(name)) {
            return fail(BarrierRemovalStage::CheckingPresence,
                        ErrorCode::InvalidControlObject,
                        "invalid barrier marker: " + name);
        }
        present_barriers.push_back(layout.barriers_prefix + name);
    }

    std::size_t remaining_barriers = 0;
    if (target_barrier.has_value()) {
        std::string canonical;
        if (*target_barrier == layout.barrier_identifier ||
            *target_barrier == "barrier") {
            canonical = layout.barrier_identifier;
        } else if (valid_barrier_identifier(layout, *target_barrier)) {
            canonical = std::string{*target_barrier};
        } else if (is_canonical_hex32(*target_barrier)) {
            canonical = layout.barriers_prefix + std::string{*target_barrier};
        } else {
            active_identifier = std::string{*target_barrier};
            return fail(BarrierRemovalStage::CheckingPresence,
                        ErrorCode::InvalidInput,
                        "invalid maintenance barrier identifier or token");
        }
        active_identifier = canonical;
        if (present_barriers.empty()) {
            auto writers = active_writers(storage, layout);
            if (!writers) {
                return with_context(BarrierRemovalStage::CheckingWriters,
                                    writers.error());
            }
            return BarrierRemovalResult{
                .outcome = BarrierRemovalOutcome::AlreadyAbsent,
                .active_writers_count = writers->size(),
                .remaining_barriers_count = 0,
            };
        }
        if (std::ranges::find(present_barriers, canonical) ==
            present_barriers.end()) {
            return fail(BarrierRemovalStage::CheckingPresence,
                        ErrorCode::InvalidInput,
                        "specified maintenance barrier is not active");
        }
        remaining_barriers = present_barriers.size() - 1;
    } else {
        if (present_barriers.empty()) {
            auto writers = active_writers(storage, layout);
            if (!writers) {
                return with_context(BarrierRemovalStage::CheckingWriters,
                                    writers.error());
            }
            return BarrierRemovalResult{
                .outcome = BarrierRemovalOutcome::AlreadyAbsent,
                .active_writers_count = writers->size(),
                .remaining_barriers_count = 0,
            };
        }
        if (present_barriers.size() > 1) {
            std::string listing;
            for (std::size_t i = 0; i < present_barriers.size(); ++i) {
                if (i > 0) {
                    listing.append(", ");
                }
                listing.append(present_barriers[i]);
            }
            active_identifier.clear();
            return std::unexpected(
                error(ErrorCode::InvalidInput,
                      "multiple maintenance barriers are active; specify "
                      "<barrier-id> explicitly: " +
                          listing,
                      std::nullopt,
                      BarrierRemovalStage::CheckingPresence,
                      BarrierRemovalMutationState::NotAttempted));
        }
        active_identifier = present_barriers.front();
        remaining_barriers = 0;
    }

    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return with_context(BarrierRemovalStage::DownloadingPayload,
                            history_error(temporary.error()));
    }
    const auto copy = (*temporary)->workspace.root / "barrier.copy";
    auto downloaded = transport::get(storage, active_identifier, copy);
    if (!downloaded) {
        if (downloaded.error().code == transport::ErrorCode::ObjectNotFound) {
            return fail(BarrierRemovalStage::DownloadingPayload,
                        ErrorCode::VerificationFailure,
                        "maintenance barrier disappeared before inspection");
        }
        return fail_tx(BarrierRemovalStage::DownloadingPayload,
                       downloaded.error(),
                       "could not download maintenance barrier");
    }
    auto observed = detail::read_file(copy, maximum_marker_size);
    if (!observed) {
        return with_context(BarrierRemovalStage::ValidatingPayload,
                            history_error(observed.error()));
    }

    std::optional<std::string_view> expected_token;
    if (active_identifier.starts_with(layout.barriers_prefix)) {
        expected_token = std::string_view{active_identifier}.substr(
            layout.barriers_prefix.size());
    }
    const auto parse_status = parse_marker_payload_impl(
        *observed, "barrier", expected_token, nullptr, nullptr);
    if (parse_status == MarkerParseError::InvalidPrefix) {
        return fail(BarrierRemovalStage::ValidatingPayload,
                    ErrorCode::InvalidControlObject,
                    "invalid barrier payload prefix");
    }
    if (parse_status == MarkerParseError::InvalidToken) {
        return fail(BarrierRemovalStage::ValidatingPayload,
                    ErrorCode::InvalidControlObject,
                    "invalid barrier token");
    }
    if (parse_status == MarkerParseError::TokenMismatch) {
        return fail(BarrierRemovalStage::ValidatingPayload,
                    ErrorCode::InvalidControlObject,
                    "barrier payload token does not match barrier identifier");
    }
    if (parse_status != MarkerParseError::Ok) {
        return fail(BarrierRemovalStage::ValidatingPayload,
                    ErrorCode::InvalidControlObject,
                    "invalid barrier payload metadata");
    }

    auto writers = active_writers(storage, layout);
    if (!writers) {
        return with_context(BarrierRemovalStage::CheckingWriters,
                            writers.error());
    }
    const std::size_t writers_count = writers->size();

    auto local_hash = crypto::physical::hash_file(copy, "sha256");
    if (!local_hash) {
        return fail(BarrierRemovalStage::VerifyingPhysicalIdentity,
                    ErrorCode::WorkspaceFailure,
                    local_hash.error());
    }

    auto matches = verify_remote_payload(
        storage, active_identifier, *observed, workspace_root, *local_hash);
    if (!matches) {
        if (matches.error().transport_failure &&
            matches.error().transport_failure->code ==
                transport::ErrorCode::ObjectNotFound) {
            return fail(BarrierRemovalStage::VerifyingPhysicalIdentity,
                        ErrorCode::VerificationFailure,
                        "maintenance barrier disappeared before removal");
        }
        return with_context(BarrierRemovalStage::VerifyingPhysicalIdentity,
                            matches.error());
    }
    if (!*matches) {
        return fail(BarrierRemovalStage::VerifyingPhysicalIdentity,
                    ErrorCode::VerificationFailure,
                    "maintenance barrier was replaced before removal");
    }

    auto removed = transport::remove(storage, active_identifier);
    if (!removed) {
        return fail_tx(BarrierRemovalStage::Removing,
                       removed.error(),
                       "could not remove maintenance barrier",
                       BarrierRemovalMutationState::Uncertain);
    }

    auto confirmed = transport::presence(storage, active_identifier);
    if (!confirmed) {
        return fail_tx(
            BarrierRemovalStage::ConfirmingAbsence,
            confirmed.error(),
            "could not confirm maintenance barrier absence after removal",
            BarrierRemovalMutationState::Uncertain);
    }
    if (*confirmed != transport::Presence::Absent) {
        return fail(BarrierRemovalStage::ConfirmingAbsence,
                    ErrorCode::VerificationFailure,
                    "maintenance barrier remains present after removal",
                    BarrierRemovalMutationState::Uncertain);
    }

    return BarrierRemovalResult{
        .outcome = *removed == transport::Removal::Removed
                       ? BarrierRemovalOutcome::Removed
                       : BarrierRemovalOutcome::AlreadyAbsent,
        .active_writers_count = writers_count,
        .remaining_barriers_count = remaining_barriers,
        .barrier_identifier = active_identifier,
    };
}

std::expected<bool, Error>
supports_online_collection(transport::Transport& storage,
                           const RemoteLayout& layout,
                           const std::filesystem::path& workspace_root) {
    auto token = platform::random::hex_id();
    if (!token) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, token.error()));
    }
    const auto name = *token;
    const auto identifier = layout.probes_prefix + name;
    const auto bytes = payload("probe", *token);
    if (auto published =
            put_verified(storage, identifier, bytes, workspace_root);
        !published) {
        return std::unexpected(published.error());
    }
    const auto cleanup = [&]() -> std::expected<void, Error> {
        auto removed = transport::remove(storage, identifier);
        if (!removed) {
            return std::unexpected(transport_error(removed.error()));
        }
        return {};
    };

    const auto probes_dir = detail::trim_trailing_slash(layout.probes_prefix);
    for (int observation = 0; observation < 2; ++observation) {
        auto listed = list_children(storage, probes_dir);
        if (!listed) {
            static_cast<void>(cleanup());
            return std::unexpected(listed.error());
        }
        if (!contains_name(*listed, name)) {
            static_cast<void>(cleanup());
            return false;
        }
    }
    if (auto removed = cleanup(); !removed) {
        return std::unexpected(removed.error());
    }
    for (int observation = 0; observation < 2; ++observation) {
        auto listed = list_children(storage, probes_dir);
        if (!listed) {
            return std::unexpected(listed.error());
        }
        if (contains_name(*listed, name)) {
            return false;
        }
    }
    return true;
}

bool is_control_object(const RemoteLayout& layout,
                       std::string_view identifier) noexcept {
    return history_storage::is_control_object(layout, identifier);
}

namespace testing {
std::vector<std::uint8_t> format_payload(std::string_view kind,
                                         std::string_view token) {
    return payload(kind, token);
}

std::vector<std::uint8_t> format_payload(std::string_view kind,
                                         std::string_view token,
                                         const MarkerMetadata& metadata) {
    return payload(kind, token, metadata);
}
} // namespace testing

} // namespace kasumi::application::history_storage::maintenance_protocol
