#include "application/history_storage/maintenance_protocol.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <ranges>
#include <span>
#include <utility>

namespace kasumi::application::history_storage::maintenance_protocol {
namespace {


constexpr std::size_t maximum_marker_size = 512;

Error error(ErrorCode code, std::string detail) {
    return Error{.code = code, .detail = std::move(detail)};
}

Error transport_error(const transport::Error& source) {
    return error(ErrorCode::TransportFailure, transport::describe(source));
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

std::vector<std::uint8_t> payload(std::string_view kind,
                                  std::string_view token) {
    constexpr std::string_view prefix = "kasumi-gc-v1:";
    const std::size_t max_allowed = std::string().max_size() - prefix.size() - 1;
    if (kind.size() > max_allowed || token.size() > (max_allowed - kind.size())) {
        return {};
    }
    const std::size_t total_size = prefix.size() + kind.size() + 1 + token.size();
    std::string value;
    value.reserve(total_size);
    value.append(prefix);
    value.append(kind);
    value.push_back(':');
    value.append(token);
    return {value.begin(), value.end()};
}

std::expected<std::vector<std::string>, Error>
list_children(transport::Transport& storage, std::string_view prefix) {
    if (storage.storage.list_prefix != nullptr) {
        auto listed = transport::list(storage, prefix);
        if (!listed &&
            listed.error().code == transport::ErrorCode::StorageNotFound) {
            return std::vector<std::string>{};
        }
        if (!listed) {
            return std::unexpected(transport_error(listed.error()));
        }
        return std::move(*listed);
    }

    auto listed = transport::list(storage);
    if (!listed &&
        listed.error().code == transport::ErrorCode::StorageNotFound) {
        return std::vector<std::string>{};
    }
    if (!listed) {
        return std::unexpected(transport_error(listed.error()));
    }
    const auto full_prefix = std::string{prefix} + '/';
    std::vector<std::string> result;
    for (const auto& identifier : *listed) {
        if (!identifier.starts_with(full_prefix)) {
            continue;
        }
        const auto name = identifier.substr(full_prefix.size());
        if (name.find('/') == std::string::npos) {
            result.push_back(name);
        }
    }
    std::ranges::sort(result);
    return result;
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
    const auto source = (*temporary)->root / "marker.source";
    const auto copy = (*temporary)->root / "marker.copy";
    if (auto written = detail::write_file(source, bytes); !written) {
        return std::unexpected(history_error(written.error()));
    }
    auto local_hash = crypto::physical::hash_file(source, "sha256");
    if (!local_hash) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, local_hash.error()));
    }
    const auto put_trace = platform::perf_trace::begin();
    auto sent = transport::put(storage, source, identifier);
    platform::perf_trace::finish("writer PUT", put_trace);
    if (!sent) {
        return std::unexpected(transport_error(sent.error()));
    }
    const auto verification_trace = platform::perf_trace::begin();
    platform::perf_trace::count("writer physical hash calls");
    auto remote_hash = transport::physical_hash(storage, identifier, "sha256");
    if (remote_hash) {
        platform::perf_trace::finish("writer verification", verification_trace);
        if (*remote_hash != *local_hash) {
            return std::unexpected(
                error(ErrorCode::VerificationFailure,
                      "remote physical hash does not match published marker"));
        }
        return *local_hash;
    }
    if (remote_hash.error().code != transport::ErrorCode::Unsupported) {
        platform::perf_trace::finish("writer verification", verification_trace);
        return std::unexpected(transport_error(remote_hash.error()));
    }
    platform::perf_trace::count("writer readback fallback");
    if (auto downloaded = detail::download(storage, identifier, copy);
        !downloaded) {
        platform::perf_trace::finish("writer verification", verification_trace);
        return std::unexpected(history_error(downloaded.error()));
    }
    auto observed = detail::read_file(copy, maximum_marker_size);
    if (!observed) {
        platform::perf_trace::finish("writer verification", verification_trace);
        return std::unexpected(history_error(observed.error()));
    }
    if (!std::ranges::equal(*observed, bytes)) {
        platform::perf_trace::finish("writer verification", verification_trace);
        return std::unexpected(
            error(ErrorCode::VerificationFailure,
                  "remote marker does not match published marker"));
    }
    platform::perf_trace::finish("writer verification", verification_trace);
    return *local_hash;
}

std::expected<bool, Error>
marker_matches(transport::Transport& storage,
               std::string_view identifier,
               std::span<const std::uint8_t> expected,
               const std::filesystem::path& workspace_root) {
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(history_error(temporary.error()));
    }
    const auto copy = (*temporary)->root / "marker.copy";
    auto downloaded = transport::get(storage, identifier, copy);
    if (!downloaded) {
        if (downloaded.error().code == transport::ErrorCode::ObjectNotFound) {
            return false;
        }
        return std::unexpected(transport_error(downloaded.error()));
    }
    auto observed = detail::read_file(copy, maximum_marker_size);
    if (!observed) {
        return std::unexpected(history_error(observed.error()));
    }
    return std::ranges::equal(*observed, expected);
}

bool contains_name(const std::vector<std::string>& names,
                   std::string_view name) {
    return std::ranges::find(names, name) != names.end();
}

bool valid_sha256(std::string_view value) {
    const auto parsed = hash_from_hex(value);
    return parsed && hash_hex(*parsed) == value;
}

std::expected<bool, Error>
registration_matches(transport::Transport& storage,
                     const RegistrationState& registration) {
    const auto ownership_trace = platform::perf_trace::begin();
    const auto result = [&]() -> std::expected<bool, Error> {
        platform::perf_trace::count("gc.barrier_ownership_verifications");
        platform::perf_trace::count("gc.barrier_physical_hash_attempts");
        const auto hash_trace = platform::perf_trace::begin();
        auto remote_hash = transport::physical_hash(
            storage, registration.identifier, "sha256");
        platform::perf_trace::finish("gc barrier physical hash verification",
                                     hash_trace);
        if (remote_hash) {
            if (!valid_sha256(*remote_hash)) {
                platform::perf_trace::count(
                    "gc.barrier_physical_hash_malformed");
                return std::unexpected(error(ErrorCode::VerificationFailure,
                                             "invalid remote barrier SHA-256"));
            }
            platform::perf_trace::count("gc.barrier_physical_hash_successes");
            if (!valid_sha256(registration.expected_physical_sha256)) {
                return std::unexpected(
                    error(ErrorCode::VerificationFailure,
                          "invalid expected barrier SHA-256"));
            }
            if (*remote_hash != registration.expected_physical_sha256) {
                platform::perf_trace::count(
                    "gc.barrier_physical_hash_mismatches");
                return false;
            }
            return true;
        }
        if (remote_hash.error().code == transport::ErrorCode::ObjectNotFound) {
            platform::perf_trace::count("gc.barrier_physical_hash_not_found");
            return false;
        }
        if (remote_hash.error().code != transport::ErrorCode::Unsupported) {
            platform::perf_trace::count("gc.barrier_physical_hash_errors");
            return std::unexpected(transport_error(remote_hash.error()));
        }

        platform::perf_trace::count("gc.barrier_physical_hash_unsupported");
        platform::perf_trace::count("gc.barrier_get_fallbacks");
        const auto fallback_trace = platform::perf_trace::begin();
        auto matches = marker_matches(storage,
                                      registration.identifier,
                                      registration.payload,
                                      registration.workspace_root);
        platform::perf_trace::finish("gc barrier GET fallback verification",
                                     fallback_trace);
        return matches;
    }();
    platform::perf_trace::finish("gc barrier ownership verification",
                                 ownership_trace);
    return result;
}

} // namespace

bool registration_active(const RegistrationState& registration) noexcept {
    return registration.storage != nullptr && !registration.identifier.empty();
}

std::expected<void, Error>
verify_registration(const RegistrationState& registration) {
    if (!registration_active(registration)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "registro remoto inativo"));
    }
    auto matches = registration_matches(*registration.storage, registration);
    if (!matches) {
        return std::unexpected(matches.error());
    }
    if (!*matches) {
        return std::unexpected(
            error(ErrorCode::Blocked,
                  "a propriedade da barreira mudou durante a coleta"));
    }
    return {};
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
    if (registration.verify_owner && *removed != transport::Removal::Removed) {
        return std::unexpected(error(ErrorCode::Blocked,
                                     "owned barrier disappeared before removal"));
    }
    return {};
}

RegistrationResult
register_writer(transport::Transport& storage,
                const RemoteLayout& layout,
                const std::filesystem::path& workspace_root) {
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
    auto bytes = payload("writer", *token);
    auto published = put_verified(storage, identifier, bytes, workspace_root);
    if (!published) {
        return std::unexpected(published.error());
    }
    RegistrationState registration{.storage = &storage,
                                   .workspace_root = workspace_root,
                                   .identifier = identifier,
                                   .payload = std::move(bytes),
                                   .expected_physical_sha256 =
                                       std::move(*published),
                                   .verify_owner = false};
    std::vector<std::string> listed;
    transport::Presence barrier = transport::Presence::Absent;
    const auto writers_dir =
        layout.writers_prefix.ends_with('/')
            ? layout.writers_prefix.substr(0, layout.writers_prefix.size() - 1)
            : layout.writers_prefix;
    const auto batch_trace = platform::perf_trace::begin();
    auto control_reads = transport::control_read_batch(
        storage,
        transport::ControlReadBatchRequest{
            .list_prefixes = {std::string{writers_dir}},
            .presence_identifiers = {layout.barrier_identifier}});
    platform::perf_trace::finish("writer admission batch", batch_trace);
    if (control_reads) {
        if (control_reads->listings.size() != 1 ||
            control_reads->presences.size() != 1) {
            auto failure = error(ErrorCode::InvalidControlObject,
                                 "incomplete admission batch response");
            static_cast<void>(release_registration(registration));
            return std::unexpected(std::move(failure));
        }
        listed = std::move(control_reads->listings.front());
        barrier = control_reads->presences.front();
    } else if (control_reads.error().code ==
               transport::ErrorCode::Unsupported) {
        const auto list_trace = platform::perf_trace::begin();
        auto sequential_list = list_children(storage, writers_dir);
        platform::perf_trace::finish("writer admission LIST", list_trace);
        if (!sequential_list) {
            auto failure = sequential_list.error();
            static_cast<void>(release_registration(registration));
            return std::unexpected(std::move(failure));
        }
        listed = std::move(*sequential_list);
        const auto barrier_trace = platform::perf_trace::begin();
        auto sequential_barrier =
            transport::presence(storage, layout.barrier_identifier);
        platform::perf_trace::finish("writer admission barrier", barrier_trace);
        if (!sequential_barrier) {
            auto failure = transport_error(sequential_barrier.error());
            static_cast<void>(release_registration(registration));
            return std::unexpected(std::move(failure));
        }
        barrier = *sequential_barrier;
    } else {
        auto failure = transport_error(control_reads.error());
        static_cast<void>(release_registration(registration));
        return std::unexpected(std::move(failure));
    }
    if (!contains_name(listed, name)) {
        auto failure = error(ErrorCode::BackendUnsafe,
                             "backend did not make writer visible in listing");
        static_cast<void>(release_registration(registration));
        return std::unexpected(std::move(failure));
    }
    if (barrier == transport::Presence::Present) {
        auto failure = error(ErrorCode::Blocked, "GC active on destination");
        static_cast<void>(release_registration(registration));
        return std::unexpected(std::move(failure));
    }
    return registration;
}

RegistrationResult
establish_barrier(transport::Transport& storage,
                  const RemoteLayout& layout,
                  const std::filesystem::path& workspace_root) {
    if (!transport::valid(storage) || workspace_root.empty()) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid barrier context"));
    }
    // Exclusive vault operation is required; this check is not an atomic lock.
    auto present = transport::presence(storage, layout.barrier_identifier);
    if (!present) {
        return std::unexpected(transport_error(present.error()));
    }
    if (*present == transport::Presence::Present) {
        return std::unexpected(
            error(ErrorCode::Blocked, "maintenance barrier already exists"));
    }
    auto token = platform::random::hex_id();
    if (!token) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, token.error()));
    }
    auto bytes = payload("barrier", *token);
    auto published =
        put_verified(storage, layout.barrier_identifier, bytes, workspace_root);
    if (!published) {
        return std::unexpected(published.error());
    }
    return RegistrationState{.storage = &storage,
                             .workspace_root = workspace_root,
                             .identifier = layout.barrier_identifier,
                             .payload = std::move(bytes),
                             .expected_physical_sha256 = std::move(*published),
                             .verify_owner = true};
}

std::expected<std::vector<std::string>, Error>
active_writers(transport::Transport& storage, const RemoteLayout& layout) {
    const auto writers_dir =
        layout.writers_prefix.ends_with('/')
            ? layout.writers_prefix.substr(0, layout.writers_prefix.size() - 1)
            : layout.writers_prefix;
    auto listed = list_children(storage, writers_dir);
    if (!listed) {
        return std::unexpected(listed.error());
    }
    std::vector<std::string> result;
    for (const auto& name : *listed) {
        if (name.size() != 32 ||
            !detail::valid_hex_id(name + std::string(32, '0'))) {
            return std::unexpected(error(ErrorCode::InvalidControlObject,
                                         "invalid writer marker: " + name));
        }
        result.push_back(layout.writers_prefix + name);
    }
    return result;
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

    auto barrier = transport::presence(storage, layout.barrier_identifier);
    if (!barrier) {
        return std::unexpected(transport_error(barrier.error()));
    }
    if (*barrier == transport::Presence::Present) {
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

bool is_control_object(const RemoteLayout& layout,
                       std::string_view identifier) noexcept {
    return history_storage::is_control_object(layout, identifier);
}

namespace testing {
std::vector<std::uint8_t> format_payload(std::string_view kind,
                                         std::string_view token) {
    return payload(kind, token);
}
}

} // namespace kasumi::application::history_storage::maintenance_protocol
