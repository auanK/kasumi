#include "application/history_storage/maintenance_protocol.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/path.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <ranges>
#include <span>
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

std::vector<std::uint8_t> payload(std::string_view kind,
                                  std::string_view token) {
    std::string value;
    value.reserve(13 + kind.size() + 1 + token.size());
    value.append("kasumi-gc-v1:");
    value.append(kind);
    value.push_back(':');
    value.append(token);
    return {value.begin(), value.end()};
}

std::expected<std::vector<std::string>, Error>
list_children(transport::Transport& storage, std::string_view prefix) {
    auto listed = detail::list_transport_identifiers(storage, prefix);
    if (!listed) {
        return std::unexpected(transport_error(listed.error()));
    }
    return std::move(*listed);
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
    auto matches = verify_remote_payload(
        storage, identifier, bytes, workspace_root, *local_hash);
    if (!matches) {
        return std::unexpected(matches.error());
    }
    if (!*matches) {
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
    auto barrier =
        transport::presence(*registration.storage, layout.barrier_identifier);
    if (!barrier) {
        return std::unexpected(transport_error(barrier.error()));
    }
    if (*barrier == transport::Presence::Present) {
        return std::unexpected(
            error(ErrorCode::Blocked, "GC active on destination"));
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
    const auto fail_releasing = [&](Error failure) {
        static_cast<void>(release_registration(registration));
        return std::unexpected(std::move(failure));
    };
    std::vector<std::string> listed;
    transport::Presence barrier = transport::Presence::Absent;
    const auto writers_dir = detail::trim_trailing_slash(layout.writers_prefix);
    auto control_reads = transport::control_read_batch(
        storage,
        transport::ControlReadBatchRequest{
            .list_prefixes = {std::string{writers_dir}},
            .presence_identifiers = {layout.barrier_identifier}});
    if (control_reads) {
        if (control_reads->listings.size() != 1 ||
            control_reads->presences.size() != 1) {
            return fail_releasing(error(ErrorCode::InvalidControlObject,
                                        "incomplete admission batch response"));
        }
        listed = std::move(control_reads->listings.front());
        barrier = control_reads->presences.front();
    } else if (control_reads.error().code ==
               transport::ErrorCode::Unsupported) {
        auto sequential_list = list_children(storage, writers_dir);
        if (!sequential_list) {
            return fail_releasing(sequential_list.error());
        }
        listed = std::move(*sequential_list);
        auto sequential_barrier =
            transport::presence(storage, layout.barrier_identifier);
        if (!sequential_barrier) {
            return fail_releasing(transport_error(sequential_barrier.error()));
        }
        barrier = *sequential_barrier;
    } else {
        return fail_releasing(transport_error(control_reads.error()));
    }
    if (!contains_name(listed, name)) {
        return fail_releasing(
            error(ErrorCode::BackendUnsafe,
                  "backend did not make writer visible in listing"));
    }
    if (barrier == transport::Presence::Present) {
        return fail_releasing(
            error(ErrorCode::Blocked, "GC active on destination"));
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

std::expected<BarrierRemovalResult, Error>
remove_barrier(transport::Transport& storage,
               const RemoteLayout& layout,
               const std::filesystem::path& workspace_root) {
    auto with_context = [&](BarrierRemovalStage stage,
                            Error err,
                            BarrierRemovalMutationState mut =
                                BarrierRemovalMutationState::NotAttempted) {
        err.identifier = layout.barrier_identifier;
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
            error(code, std::move(msg), layout.barrier_identifier, stage, mut));
    };
    auto fail_tx = [&](BarrierRemovalStage stage,
                       const transport::Error& err,
                       std::string msg,
                       BarrierRemovalMutationState mut =
                           BarrierRemovalMutationState::NotAttempted) {
        return std::unexpected(transport_error(
            err, std::move(msg), layout.barrier_identifier, stage, mut));
    };

    if (!transport::valid(storage) || workspace_root.empty()) {
        return fail(BarrierRemovalStage::CheckingPresence,
                    ErrorCode::InvalidInput,
                    "invalid barrier removal context");
    }

    auto present = transport::presence(storage, layout.barrier_identifier);
    if (!present) {
        return fail_tx(BarrierRemovalStage::CheckingPresence,
                       present.error(),
                       "could not check maintenance barrier presence");
    }
    if (*present == transport::Presence::Absent) {
        auto writers = active_writers(storage, layout);
        if (!writers) {
            return with_context(BarrierRemovalStage::CheckingWriters,
                                writers.error());
        }
        return BarrierRemovalResult{
            .outcome = BarrierRemovalOutcome::AlreadyAbsent,
            .active_writers_count = writers->size(),
        };
    }

    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return with_context(BarrierRemovalStage::DownloadingPayload,
                            history_error(temporary.error()));
    }
    const auto copy = (*temporary)->workspace.root / "barrier.copy";
    auto downloaded = transport::get(storage, layout.barrier_identifier, copy);
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

    constexpr std::string_view prefix = "kasumi-gc-v1:barrier:";
    const std::string_view payload_sv{
        reinterpret_cast<const char*>(observed->data()), observed->size()};
    if (!payload_sv.starts_with(prefix)) {
        return fail(BarrierRemovalStage::ValidatingPayload,
                    ErrorCode::InvalidControlObject,
                    "invalid barrier payload prefix");
    }
    if (!is_canonical_hex32(payload_sv.substr(prefix.size()))) {
        return fail(BarrierRemovalStage::ValidatingPayload,
                    ErrorCode::InvalidControlObject,
                    "invalid barrier token");
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

    auto matches = verify_remote_payload(storage,
                                         layout.barrier_identifier,
                                         *observed,
                                         workspace_root,
                                         *local_hash);
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

    auto removed = transport::remove(storage, layout.barrier_identifier);
    if (!removed) {
        return fail_tx(BarrierRemovalStage::Removing,
                       removed.error(),
                       "could not remove maintenance barrier",
                       BarrierRemovalMutationState::Uncertain);
    }

    present = transport::presence(storage, layout.barrier_identifier);
    if (!present) {
        return fail_tx(
            BarrierRemovalStage::ConfirmingAbsence,
            present.error(),
            "could not confirm maintenance barrier absence after removal",
            BarrierRemovalMutationState::Uncertain);
    }
    if (*present != transport::Presence::Absent) {
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
} // namespace testing

} // namespace kasumi::application::history_storage::maintenance_protocol
