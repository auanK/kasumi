#include "application/history_storage/maintenance_protocol.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/perf_trace.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <charconv>
#include <map>
#include <ranges>
#include <span>
#include <utility>

namespace kasumi::application::history_storage::maintenance_protocol {
namespace {

constexpr std::string_view protocol_prefix = "history/gc/v1/";
constexpr std::string_view barrier_identifier = "history/gc/v1/barrier";
constexpr std::string_view writers_prefix = "history/gc/v1/writers";
constexpr std::string_view probes_prefix = "history/gc/v1/probes";
constexpr std::string_view quarantine_prefix = "history/gc/v1/quarantine/";
constexpr std::string_view quarantine_content_prefix =
    "history/gc/v1/quarantine/content/";
constexpr std::string_view quarantine_commit_prefix =
    "history/gc/v1/quarantine/commits/";
constexpr std::string_view metadata_suffix = ".meta";
constexpr std::string_view metadata_magic = "KGQ1\n";
constexpr std::size_t maximum_marker_size = 512;
constexpr std::size_t maximum_metadata_plaintext_size = 96;

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
    const auto value =
        "kasumi-gc-v1:" + std::string{kind} + ':' + std::string{token};
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

std::expected<void, Error>
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
        return {};
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
    return {};
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

std::optional<std::string>
original_from_quarantine(const RemoteLayout& layout,
                         std::string_view identifier) {
    return restore_destination(layout, identifier);
}

bool valid_sha256(std::string_view value) {
    const auto parsed = hash_from_hex(value);
    return parsed && hash_hex(*parsed) == value;
}

std::string metadata_for(std::string_view quarantine_identifier) {
    return std::string{quarantine_identifier} + std::string{metadata_suffix};
}

std::optional<std::string>
quarantine_from_metadata(const RemoteLayout& layout,
                         std::string_view identifier) {
    const bool is_quarantine =
        identifier.starts_with(layout.quarantine_prefix) ||
        identifier.starts_with("history/gc/v1/quarantine/") ||
        identifier.starts_with("history/gc/quarantine/");
    if (!is_quarantine || !identifier.ends_with(metadata_suffix)) {
        return std::nullopt;
    }
    auto quarantine = std::string{
        identifier.substr(0, identifier.size() - metadata_suffix.size())};
    return original_from_quarantine(layout, quarantine)
               ? std::move(quarantine)
               : std::optional<std::string>{};
}

std::expected<std::string, Error>
object_sha256(transport::Transport& storage,
              std::string_view identifier,
              const std::filesystem::path& workspace_root) {
    auto remote = transport::physical_hash(storage, identifier, "sha256");
    if (remote) {
        if (!valid_sha256(*remote)) {
            return std::unexpected(error(ErrorCode::VerificationFailure,
                                         "invalid remote SHA-256"));
        }
        return std::move(*remote);
    }
    if (remote.error().code != transport::ErrorCode::Unsupported) {
        return std::unexpected(transport_error(remote.error()));
    }

    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(history_error(temporary.error()));
    }
    const auto copy = (*temporary)->root / "object.copy";
    if (auto downloaded = detail::download(storage, identifier, copy);
        !downloaded) {
        return std::unexpected(history_error(downloaded.error()));
    }
    auto hash = crypto::physical::hash_file(copy, "sha256");
    if (!hash) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, hash.error()));
    }
    return std::move(*hash);
}

std::vector<std::uint8_t> encode_metadata(std::int64_t quarantined_at,
                                          std::string_view physical_sha256) {
    const auto value = std::string{metadata_magic} +
                       std::to_string(quarantined_at) + '\n' +
                       std::string{physical_sha256} + '\n';
    return {value.begin(), value.end()};
}

std::expected<std::pair<std::int64_t, std::string>, Error>
decode_metadata(std::span<const std::uint8_t> bytes) {
    const auto text = std::string_view{
        reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    if (!text.starts_with(metadata_magic)) {
        return std::unexpected(error(ErrorCode::InvalidControlObject,
                                     "invalid quarantine metadata"));
    }
    const auto body = text.substr(metadata_magic.size());
    const auto separator = body.find('\n');
    if (separator == std::string_view::npos) {
        return std::unexpected(error(ErrorCode::InvalidControlObject,
                                     "invalid quarantine metadata"));
    }
    std::int64_t quarantined_at = -1;
    const auto timestamp = body.substr(0, separator);
    const auto [end, parse_error] = std::from_chars(
        timestamp.data(), timestamp.data() + timestamp.size(), quarantined_at);
    const auto physical_sha256 = body.substr(separator + 1);
    if (parse_error != std::errc{} ||
        end != timestamp.data() + timestamp.size() || quarantined_at < 0 ||
        physical_sha256.size() != 65 || !physical_sha256.ends_with('\n') ||
        !valid_sha256(physical_sha256.substr(0, 64))) {
        return std::unexpected(error(ErrorCode::InvalidControlObject,
                                     "invalid quarantine metadata"));
    }
    return std::pair{quarantined_at,
                     std::string{physical_sha256.substr(0, 64)}};
}

std::expected<std::pair<std::int64_t, std::string>, Error>
load_metadata(transport::Transport& storage,
              std::string_view identifier,
              std::span<const std::uint8_t, crypto::KEY_SIZE> key,
              const std::filesystem::path& workspace_root) {
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(history_error(temporary.error()));
    }
    const auto encrypted = (*temporary)->root / "metadata.enc";
    const auto plaintext = (*temporary)->root / "metadata.plain";
    if (auto downloaded = detail::download(storage, identifier, encrypted);
        !downloaded) {
        return std::unexpected(history_error(downloaded.error()));
    }
    std::error_code file_error;
    if (std::filesystem::file_size(encrypted, file_error) >
            maximum_marker_size ||
        file_error) {
        return std::unexpected(error(ErrorCode::InvalidControlObject,
                                     "quarantine metadata too large"));
    }
    if (!crypto::decrypt_file(
            encrypted, plaintext, key, crypto::FilePurpose::History)) {
        return std::unexpected(error(ErrorCode::VerificationFailure,
                                     "quarantine metadata not authenticated"));
    }
    auto bytes = detail::read_file(plaintext, maximum_metadata_plaintext_size);
    if (!bytes) {
        return std::unexpected(history_error(bytes.error()));
    }
    return decode_metadata(*bytes);
}

std::expected<void, Error>
publish_metadata(transport::Transport& storage,
                 std::string_view identifier,
                 std::int64_t quarantined_at,
                 std::string_view physical_sha256,
                 std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                 const std::filesystem::path& workspace_root) {
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(history_error(temporary.error()));
    }
    const auto plaintext = (*temporary)->root / "metadata.plain";
    const auto encrypted = (*temporary)->root / "metadata.enc";
    const auto bytes = encode_metadata(quarantined_at, physical_sha256);
    if (auto written = detail::write_file(plaintext, bytes); !written) {
        return std::unexpected(history_error(written.error()));
    }
    if (!crypto::encrypt_file(
            plaintext, encrypted, key, crypto::FilePurpose::History)) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, "failed to encrypt metadata"));
    }
    auto ciphertext = detail::read_file(encrypted, maximum_marker_size);
    if (!ciphertext) {
        return std::unexpected(history_error(ciphertext.error()));
    }
    return put_verified(storage, identifier, *ciphertext, workspace_root);
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
    auto matches = marker_matches(*registration.storage,
                                  registration.identifier,
                                  registration.payload,
                                  registration.workspace_root);
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
        auto matches = marker_matches(*storage,
                                      registration.identifier,
                                      registration.payload,
                                      registration.workspace_root);
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
    if (auto published =
            put_verified(storage, identifier, bytes, workspace_root);
        !published) {
        return std::unexpected(published.error());
    }
    RegistrationState registration{.storage = &storage,
                                   .workspace_root = workspace_root,
                                   .identifier = identifier,
                                   .payload = std::move(bytes),
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
register_writer(transport::Transport& storage,
                const std::filesystem::path& workspace_root) {
    return register_writer(storage, default_remote_layout(), workspace_root);
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
    if (auto published = put_verified(
            storage, layout.barrier_identifier, bytes, workspace_root);
        !published) {
        return std::unexpected(published.error());
    }
    return RegistrationState{.storage = &storage,
                             .workspace_root = workspace_root,
                             .identifier = layout.barrier_identifier,
                             .payload = std::move(bytes),
                             .verify_owner = true};
}

RegistrationResult
establish_barrier(transport::Transport& storage,
                  const std::filesystem::path& workspace_root) {
    return establish_barrier(storage, default_remote_layout(), workspace_root);
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

std::expected<std::vector<std::string>, Error>
active_writers(transport::Transport& storage) {
    return active_writers(storage, default_remote_layout());
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

    const auto probes_dir =
        layout.probes_prefix.ends_with('/')
            ? layout.probes_prefix.substr(0, layout.probes_prefix.size() - 1)
            : layout.probes_prefix;
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

std::expected<bool, Error>
supports_online_collection(transport::Transport& storage,
                           const std::filesystem::path& workspace_root) {
    return supports_online_collection(
        storage, default_remote_layout(), workspace_root);
}

bool is_epoch_object(const RemoteLayout& layout,
                     std::string_view identifier) noexcept {
    return identifier.starts_with(layout.epochs_prefix);
}

bool is_epoch_object(std::string_view identifier) noexcept {
    return identifier.starts_with(epoch_namespace_prefix);
}

bool is_control_object(const RemoteLayout& layout,
                       std::string_view identifier) noexcept {
    return history_storage::is_control_object(layout, identifier);
}

bool is_control_object(std::string_view identifier) noexcept {
    return history_storage::is_control_object(default_remote_layout(),
                                              identifier);
}

std::optional<std::string>
quarantine_identifier(const RemoteLayout& layout,
                      std::string_view original_identifier) {
    return history_storage::quarantine_identifier(layout, original_identifier);
}

std::optional<std::string>
quarantine_identifier(std::string_view original_identifier) {
    return history_storage::quarantine_identifier(default_remote_layout(),
                                                  original_identifier);
}

namespace {

std::expected<std::vector<QuarantineEntry>, Error> inventory_quarantine_impl(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::optional<std::span<const std::string>> identifiers,
    const std::filesystem::path& workspace_root) {
    const auto layout = derive_remote_layout(key);
    std::span<const std::string> listing_span;
    std::vector<std::string> fallback_listing;
    if (identifiers) {
        listing_span = *identifiers;
    } else {
        auto listed = transport::list(storage);
        if (!listed) {
            return std::unexpected(transport_error(listed.error()));
        }
        fallback_listing = std::move(*listed);
        listing_span = fallback_listing;
    }

    std::map<std::string, QuarantineEntry> entries;
    std::map<std::string, std::string> metadata;
    for (const auto& identifier : listing_span) {
        if (!history_storage::is_control_object(layout, identifier) ||
            identifier == layout.barrier_identifier ||
            identifier == "history/gc/v1/barrier" ||
            identifier == "history/gc/barrier" ||
            identifier.starts_with(layout.writers_prefix) ||
            identifier.starts_with("history/gc/v1/writers/") ||
            identifier.starts_with("history/gc/writers/") ||
            identifier.starts_with(layout.probes_prefix) ||
            identifier.starts_with("history/gc/v1/probes/") ||
            identifier.starts_with("history/gc/probes/")) {
            continue;
        }
        const bool is_quarantine =
            identifier.starts_with(layout.quarantine_prefix) ||
            identifier.starts_with("history/gc/v1/quarantine/") ||
            identifier.starts_with("history/gc/quarantine/");
        if (!is_quarantine) {
            return std::unexpected(
                error(ErrorCode::InvalidControlObject,
                      "unexpected control object: " + identifier));
        }
        if (auto quarantine = quarantine_from_metadata(layout, identifier)) {
            metadata.emplace(std::move(*quarantine), identifier);
            continue;
        }
        auto original = restore_destination(layout, identifier);
        if (!original) {
            return std::unexpected(
                error(ErrorCode::InvalidControlObject,
                      "invalid quarantine object: " + identifier));
        }
        entries.emplace(identifier,
                        QuarantineEntry{
                            .original_identifier = std::move(*original),
                            .quarantine_identifier = identifier,
                            .metadata_identifier = metadata_for(identifier),
                            .quarantined_at = std::nullopt,
                            .physical_sha256 = {},
                        });
    }

    for (const auto& [quarantine_identifier, metadata_identifier] : metadata) {
        const auto entry = entries.find(quarantine_identifier);
        if (entry == entries.end()) {
            return std::unexpected(error(
                ErrorCode::InvalidControlObject,
                "metadata without quarantine object: " + metadata_identifier));
        }
        auto loaded =
            load_metadata(storage, metadata_identifier, key, workspace_root);
        if (!loaded) {
            return std::unexpected(loaded.error());
        }
        entry->second.quarantined_at = loaded->first;
        entry->second.physical_sha256 = std::move(loaded->second);
    }

    std::vector<QuarantineEntry> result;
    result.reserve(entries.size());
    for (auto& [unused, entry] : entries) {
        static_cast<void>(unused);
        result.push_back(std::move(entry));
    }
    std::ranges::sort(result, {}, &QuarantineEntry::original_identifier);
    return result;
}

} // namespace

std::expected<std::vector<QuarantineEntry>, Error>
inventory_quarantine(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const std::filesystem::path& workspace_root) {
    return inventory_quarantine_impl(
        storage, key, std::nullopt, workspace_root);
}

std::expected<std::vector<QuarantineEntry>, Error>
inventory_quarantine(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     std::span<const std::string> identifiers,
                     const std::filesystem::path& workspace_root) {
    return inventory_quarantine_impl(storage, key, identifiers, workspace_root);
}

std::expected<QuarantineEntry, Error>
record_quarantine(transport::Transport& storage,
                  std::string_view quarantine_identifier,
                  std::int64_t quarantined_at,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                  const std::filesystem::path& workspace_root,
                  std::string_view verified_sha256) {
    const auto layout = derive_remote_layout(key);
    auto original = restore_destination(layout, quarantine_identifier);
    if (!original || quarantined_at < 0) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid quarantine record"));
    }
    std::string physical_sha256{verified_sha256};
    if (physical_sha256.empty()) {
        auto observed =
            object_sha256(storage, quarantine_identifier, workspace_root);
        if (!observed) {
            return std::unexpected(observed.error());
        }
        physical_sha256 = std::move(*observed);
    } else if (!valid_sha256(physical_sha256)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid quarantine SHA-256"));
    }
    const auto metadata_identifier = metadata_for(quarantine_identifier);
    auto published = publish_metadata(storage,
                                      metadata_identifier,
                                      quarantined_at,
                                      physical_sha256,
                                      key,
                                      workspace_root);
    if (!published) {
        return std::unexpected(published.error());
    }
    return QuarantineEntry{
        .original_identifier = std::move(*original),
        .quarantine_identifier = std::string{quarantine_identifier},
        .metadata_identifier = metadata_identifier,
        .quarantined_at = quarantined_at,
        .physical_sha256 = std::move(physical_sha256),
    };
}

std::expected<bool, Error>
verify_quarantine(transport::Transport& storage,
                  const QuarantineEntry& entry,
                  const std::filesystem::path& workspace_root) {
    if (!entry.quarantined_at || !valid_sha256(entry.physical_sha256) ||
        metadata_for(entry.quarantine_identifier) !=
            entry.metadata_identifier) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "missing quarantine metadata"));
    }
    auto physical_sha256 =
        object_sha256(storage, entry.quarantine_identifier, workspace_root);
    if (!physical_sha256) {
        return std::unexpected(physical_sha256.error());
    }
    return *physical_sha256 == entry.physical_sha256;
}

std::expected<void, Error>
verify_destination_via_workspace(
    transport::Transport& storage,
    std::string_view destination_identifier,
    std::string_view expected_sha256,
    const std::filesystem::path& workspace_root) {
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(history_error(temporary.error()));
    }
    const auto destination = (*temporary)->root / "destination.object";
    if (auto downloaded =
            detail::download(storage, destination_identifier, destination);
        !downloaded) {
        return std::unexpected(history_error(downloaded.error()));
    }
    auto destination_hash = crypto::physical::hash_file(destination, "sha256");
    if (!destination_hash) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, destination_hash.error()));
    }
    if (*destination_hash != expected_sha256) {
        return std::unexpected(
            error(ErrorCode::VerificationFailure,
                  "downloaded copy does not match source object"));
    }
    return {};
}

std::expected<std::string, Error>
copy_verified_via_workspace(
    transport::Transport& storage,
    std::string_view source_identifier,
    std::string_view destination_identifier,
    const std::filesystem::path& workspace_root) {
    if (is_epoch_object(source_identifier) ||
        is_epoch_object(destination_identifier)) {
        return std::unexpected(
            error(ErrorCode::Blocked,
                  "epoch objects cannot be copied by collection"));
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(history_error(temporary.error()));
    }
    const auto source = (*temporary)->root / "source.object";
    const auto destination = (*temporary)->root / "destination.object";
    if (auto downloaded = detail::download(storage, source_identifier, source);
        !downloaded) {
        return std::unexpected(history_error(downloaded.error()));
    }
    auto source_hash = crypto::physical::hash_file(source, "sha256");
    if (!source_hash) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, source_hash.error()));
    }
    if (auto sent = transport::put(storage, source, destination_identifier);
        !sent) {
        return std::unexpected(transport_error(sent.error()));
    }

    auto remote_hash =
        transport::physical_hash(storage, destination_identifier, "sha256");
    if (remote_hash) {
        if (*remote_hash != *source_hash) {
            return std::unexpected(
                error(ErrorCode::VerificationFailure,
                      "remote copy does not match source object"));
        }
        return std::move(*source_hash);
    }
    if (remote_hash.error().code != transport::ErrorCode::Unsupported) {
        return std::unexpected(transport_error(remote_hash.error()));
    }

    if (auto downloaded =
            detail::download(storage, destination_identifier, destination);
        !downloaded) {
        return std::unexpected(history_error(downloaded.error()));
    }
    auto destination_hash = crypto::physical::hash_file(destination, "sha256");
    if (!destination_hash) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, destination_hash.error()));
    }
    if (*destination_hash != *source_hash) {
        return std::unexpected(
            error(ErrorCode::VerificationFailure,
                  "downloaded copy does not match source object"));
    }
    return std::move(*source_hash);
}

std::expected<std::string, Error>
copy_verified(transport::Transport& storage,
              std::string_view source_identifier,
              std::string_view destination_identifier,
              const std::filesystem::path& workspace_root) {
    if (is_epoch_object(source_identifier) ||
        is_epoch_object(destination_identifier)) {
        return std::unexpected(
            error(ErrorCode::Blocked,
                  "epoch objects cannot be copied by collection"));
    }
    const auto source_hash_trace = platform::perf_trace::begin();
    auto source_hash =
        transport::physical_hash(storage, source_identifier, "sha256");
    platform::perf_trace::finish("verified copy source physical hash",
                                 source_hash_trace);
    if (source_hash) {
        if (!valid_sha256(*source_hash)) {
            return std::unexpected(
                error(ErrorCode::VerificationFailure,
                      "invalid source physical SHA-256"));
        }
        const auto native_copy_trace = platform::perf_trace::begin();
        auto copied = transport::copy(
            storage, source_identifier, destination_identifier);
        platform::perf_trace::finish("verified copy native copy",
                                     native_copy_trace);
        if (copied) {
            platform::perf_trace::count(
                "verified copy native copy successes");
            const auto destination_hash_trace =
                platform::perf_trace::begin();
            auto destination_hash =
                transport::physical_hash(storage,
                                         destination_identifier,
                                         "sha256");
            platform::perf_trace::finish(
                "verified copy destination physical hash",
                destination_hash_trace);
            if (destination_hash) {
                if (!valid_sha256(*destination_hash)) {
                    return std::unexpected(
                        error(ErrorCode::VerificationFailure,
                              "invalid destination physical SHA-256"));
                }
                if (*destination_hash != *source_hash) {
                    return std::unexpected(
                        error(ErrorCode::VerificationFailure,
                              "remote copy does not match source object"));
                }
                platform::perf_trace::count(
                    "verified copy native copy verifications");
                return std::move(*source_hash);
            }
            if (destination_hash.error().code !=
                transport::ErrorCode::Unsupported) {
                return std::unexpected(
                    transport_error(destination_hash.error()));
            }
            auto verified = verify_destination_via_workspace(
                storage, destination_identifier, *source_hash, workspace_root);
            if (!verified) {
                return std::unexpected(verified.error());
            }
            platform::perf_trace::count(
                "verified copy native copy verifications");
            return std::move(*source_hash);
        }
        if (copied.error().code != transport::ErrorCode::Unsupported) {
            return std::unexpected(transport_error(copied.error()));
        }
    } else if (source_hash.error().code !=
               transport::ErrorCode::Unsupported) {
        return std::unexpected(transport_error(source_hash.error()));
    }

    return copy_verified_via_workspace(
        storage, source_identifier, destination_identifier, workspace_root);
}

} // namespace kasumi::application::history_storage::maintenance_protocol
