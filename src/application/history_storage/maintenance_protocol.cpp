#include "application/history_storage/maintenance_protocol.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/cancellation.hpp"
#include "platform/durability.hpp"
#include "platform/machine.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <mutex>
#include <ranges>
#include <span>
#include <thread>
#include <unordered_set>
#include <utility>

namespace kasumi::application::history_storage::maintenance_protocol {
namespace {

std::mutex& active_pending_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::unordered_set<std::string>& active_pending_identifiers() {
    static auto* identifiers = new std::unordered_set<std::string>();
    return *identifiers;
}

bool is_pending_identifier_active(std::string_view identifier) {
    std::scoped_lock lock(active_pending_mutex());
    return active_pending_identifiers().contains(std::string{identifier});
}

struct ActivePendingGuard {
    std::string identifier;

    explicit ActivePendingGuard(std::string id) : identifier(std::move(id)) {
        std::scoped_lock lock(active_pending_mutex());
        active_pending_identifiers().insert(identifier);
    }

    ~ActivePendingGuard() {
        std::scoped_lock lock(active_pending_mutex());
        active_pending_identifiers().erase(identifier);
    }

    ActivePendingGuard(const ActivePendingGuard&) = delete;
    ActivePendingGuard& operator=(const ActivePendingGuard&) = delete;
    ActivePendingGuard(ActivePendingGuard&&) = delete;
    ActivePendingGuard& operator=(ActivePendingGuard&&) = delete;
};

constexpr std::size_t maximum_marker_size = 512;
constexpr std::size_t TOKEN_HEX_SIZE = 32;

bool is_canonical_hex32(std::string_view value) noexcept {
    return value.size() == TOKEN_HEX_SIZE &&
           std::ranges::all_of(value, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

bool is_lower_hex16(std::string_view value) noexcept {
    return value.size() == 16U &&
           std::ranges::all_of(value, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

std::optional<std::string_view>
parse_legacy_local_staging_name(std::string_view name) noexcept {
    constexpr std::string_view kTmpMarker = ".kasumi-tmp-";
    constexpr std::size_t kExpectedLength = TOKEN_HEX_SIZE + 12U + 16U;
    if (name.size() != kExpectedLength) {
        return std::nullopt;
    }
    const auto token = name.substr(0, TOKEN_HEX_SIZE);
    const auto marker = name.substr(TOKEN_HEX_SIZE, kTmpMarker.size());
    const auto nonce = name.substr(TOKEN_HEX_SIZE + kTmpMarker.size());
    if (!is_canonical_hex32(token) || marker != kTmpMarker ||
        !is_lower_hex16(nonce)) {
        return std::nullopt;
    }
    return token;
}

enum class ControlEntryKind {
    PublishedMarker,
    LegacyStagingResidue,
    Unknown,
};

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

std::expected<ControlEntryKind, Error>
classify_control_entry(transport::Transport& storage,
                       std::string_view prefix,
                       std::string_view name,
                       std::string_view expected_kind,
                       const std::filesystem::path* workspace_root) {
    if (is_canonical_hex32(name)) {
        return ControlEntryKind::PublishedMarker;
    }
    const auto token = parse_legacy_local_staging_name(name);
    if (!token) {
        return ControlEntryKind::Unknown;
    }

    std::optional<platform::Workspace> owned_workspace;
    std::filesystem::path copy;
    detail::TemporaryWorkspace scoped_workspace{nullptr, detail::remove_workspace};
    if (workspace_root != nullptr && !workspace_root->empty()) {
        auto temp = detail::make_workspace(*workspace_root);
        if (!temp) {
            return std::unexpected(history_error(temp.error()));
        }
        scoped_workspace = std::move(*temp);
        copy = scoped_workspace->workspace.root / "control.inspect";
    } else {
        auto temp = platform::create_workspace("control-inspect");
        if (!temp) {
            return std::unexpected(
                error(ErrorCode::WorkspaceFailure, temp.error()));
        }
        owned_workspace = std::move(*temp);
        copy = owned_workspace->root / "control.inspect";
    }
    struct OwnedWorkspaceCleanup {
        std::optional<platform::Workspace>& workspace;
        ~OwnedWorkspaceCleanup() noexcept {
            if (workspace) {
                platform::cleanup_workspace(*workspace);
            }
        }
    } cleanup{owned_workspace};

    const std::string identifier = std::string{prefix} + std::string{name};
    auto downloaded = transport::get(storage, identifier, copy);
    if (!downloaded) {
        if (downloaded.error().code == transport::ErrorCode::ObjectNotFound) {
            return ControlEntryKind::LegacyStagingResidue;
        }
        return std::unexpected(transport_error(downloaded.error()));
    }
    auto bytes = detail::read_file(copy, maximum_marker_size);
    if (!bytes) {
        return ControlEntryKind::Unknown;
    }
    if (parse_marker_payload_impl(
            *bytes, expected_kind, *token, nullptr, nullptr) ==
        MarkerParseError::Ok) {
        return ControlEntryKind::LegacyStagingResidue;
    }
    return ControlEntryKind::Unknown;
}

struct ControlReadSnapshot {
    std::vector<std::string> writers;
    std::vector<std::string> legacy_writer_staging;
    std::vector<std::string> unknown_writers;
    std::vector<std::string> barrier_tokens;
    std::vector<std::string> legacy_barrier_staging;
    std::vector<std::string> unknown_barriers;
    transport::Presence legacy_barrier = transport::Presence::Absent;
};

std::expected<ControlReadSnapshot, Error> classify_control_snapshot(
    transport::Transport& storage,
    const RemoteLayout& layout,
    std::vector<std::string> raw_writers,
    std::vector<std::string> raw_barriers,
    transport::Presence legacy_barrier,
    bool include_writers,
    const std::filesystem::path* workspace_root) {
    ControlReadSnapshot snapshot;
    snapshot.legacy_barrier = legacy_barrier;
    if (include_writers) {
        for (auto& name : raw_writers) {
            auto kind = classify_control_entry(
                storage, layout.writers_prefix, name, "writer", workspace_root);
            if (!kind) {
                return std::unexpected(kind.error());
            }
            switch (*kind) {
                case ControlEntryKind::PublishedMarker:
                    snapshot.writers.push_back(std::move(name));
                    break;
                case ControlEntryKind::LegacyStagingResidue:
                    snapshot.legacy_writer_staging.push_back(std::move(name));
                    break;
                case ControlEntryKind::Unknown:
                    snapshot.unknown_writers.push_back(std::move(name));
                    break;
            }
        }
    }
    for (auto& name : raw_barriers) {
        auto kind = classify_control_entry(
            storage, layout.barriers_prefix, name, "barrier", workspace_root);
        if (!kind) {
            return std::unexpected(kind.error());
        }
        switch (*kind) {
            case ControlEntryKind::PublishedMarker:
                snapshot.barrier_tokens.push_back(std::move(name));
                break;
            case ControlEntryKind::LegacyStagingResidue:
                snapshot.legacy_barrier_staging.push_back(std::move(name));
                break;
            case ControlEntryKind::Unknown:
                snapshot.unknown_barriers.push_back(std::move(name));
                break;
        }
    }
    return snapshot;
}

std::expected<ControlReadSnapshot, Error>
read_control_snapshot(transport::Transport& storage,
                      const RemoteLayout& layout,
                      bool include_writers,
                      const std::filesystem::path* workspace_root = nullptr) {
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
        if (include_writers) {
            return classify_control_snapshot(storage,
                                             layout,
                                             std::move(batch->listings[0]),
                                             std::move(batch->listings[1]),
                                             batch->presences[0],
                                             true,
                                             workspace_root);
        }
        return classify_control_snapshot(storage,
                                         layout,
                                         {},
                                         std::move(batch->listings[0]),
                                         batch->presences[0],
                                         false,
                                         workspace_root);
    }
    if (batch.error().code != transport::ErrorCode::Unsupported) {
        return std::unexpected(transport_error(batch.error()));
    }

    std::vector<std::string> writers_raw;
    if (include_writers) {
        auto writers = list_children(storage, writers_dir);
        if (!writers) {
            return std::unexpected(writers.error());
        }
        writers_raw = std::move(*writers);
    }
    auto barriers = list_children(storage, barriers_dir);
    if (!barriers) {
        return std::unexpected(barriers.error());
    }
    auto legacy = transport::presence(storage, layout.barrier_identifier);
    if (!legacy) {
        return std::unexpected(transport_error(legacy.error()));
    }
    return classify_control_snapshot(storage,
                                     layout,
                                     std::move(writers_raw),
                                     std::move(*barriers),
                                     *legacy,
                                     include_writers,
                                     workspace_root);
}

std::expected<void, Error>
validate_known_controls(const ControlReadSnapshot& snapshot,
                        bool check_writers) {
    if (!snapshot.unknown_barriers.empty()) {
        return std::unexpected(
            error(ErrorCode::InvalidControlObject,
                  "invalid barrier marker: " + snapshot.unknown_barriers.front()));
    }
    if (check_writers && !snapshot.unknown_writers.empty()) {
        return std::unexpected(
            error(ErrorCode::InvalidControlObject,
                  "invalid writer marker: " + snapshot.unknown_writers.front()));
    }
    return {};
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

std::string hex_encode_bytes(std::span<const std::uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const auto byte : bytes) {
        out.push_back(kHex[(byte >> 4U) & 0x0FU]);
        out.push_back(kHex[byte & 0x0FU]);
    }
    return out;
}

std::optional<std::vector<std::uint8_t>>
hex_decode_bytes(std::string_view hex) {
    if ((hex.size() % 2U) != 0U) {
        return std::nullopt;
    }
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return 10 + (c - 'a');
        }
        return -1;
    };
    std::vector<std::uint8_t> bytes;
    bytes.reserve(hex.size() / 2U);
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1U]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        bytes.push_back(static_cast<std::uint8_t>((hi << 4U) | lo));
    }
    return bytes;
}

std::filesystem::path
pending_markers_directory(const std::filesystem::path& workspace_root) {
    return workspace_root / ".pending-control-markers";
}

std::filesystem::path
pending_marker_path(const std::filesystem::path& workspace_root,
                    std::string_view kind,
                    std::string_view token) {
    return pending_markers_directory(workspace_root) /
           (std::string{kind} + "-" + std::string{token});
}

struct PendingMarkerRecord {
    std::string kind;
    std::string identifier;
    std::string token;
    std::string expected_physical_sha256;
    std::vector<std::uint8_t> payload;
};

std::string serialize_pending_record(std::string_view kind,
                                     const RegistrationState& registration) {
    std::string serialized;
    serialized.reserve(256 + registration.identifier.size() +
                       registration.payload.size() * 2U);
    serialized.append("kasumi-pending-marker-v1\nkind=");
    serialized.append(kind);
    serialized.append("\nidentifier=");
    serialized.append(registration.identifier);
    serialized.append("\ntoken=");
    serialized.append(registration.token);
    serialized.append("\nsha256=");
    serialized.append(registration.expected_physical_sha256);
    serialized.append("\npayload_hex=");
    serialized.append(hex_encode_bytes(registration.payload));
    serialized.push_back('\n');
    return serialized;
}

std::optional<PendingMarkerRecord>
parse_pending_record(std::span<const std::uint8_t> bytes) {
    const std::string_view text{reinterpret_cast<const char*>(bytes.data()),
                                bytes.size()};
    if (text.find('\r') != std::string_view::npos) {
        return std::nullopt;
    }
    constexpr std::string_view kHeader = "kasumi-pending-marker-v1\n";
    if (!text.starts_with(kHeader)) {
        return std::nullopt;
    }
    PendingMarkerRecord record;
    bool seen_kind = false;
    bool seen_id = false;
    bool seen_token = false;
    bool seen_sha = false;
    bool seen_payload = false;
    std::string_view rest = text.substr(kHeader.size());
    while (!rest.empty()) {
        const auto nl = rest.find('\n');
        const auto line =
            nl == std::string_view::npos ? rest : rest.substr(0, nl);
        if (line.empty()) {
            return std::nullopt;
        }
        if (line.starts_with("kind=")) {
            if (seen_kind) {
                return std::nullopt;
            }
            record.kind = std::string{line.substr(5)};
            seen_kind = true;
        } else if (line.starts_with("identifier=")) {
            if (seen_id) {
                return std::nullopt;
            }
            record.identifier = std::string{line.substr(11)};
            seen_id = true;
        } else if (line.starts_with("token=")) {
            if (seen_token) {
                return std::nullopt;
            }
            record.token = std::string{line.substr(6)};
            seen_token = true;
        } else if (line.starts_with("sha256=")) {
            if (seen_sha) {
                return std::nullopt;
            }
            record.expected_physical_sha256 = std::string{line.substr(7)};
            seen_sha = true;
        } else if (line.starts_with("payload_hex=")) {
            if (seen_payload) {
                return std::nullopt;
            }
            auto decoded = hex_decode_bytes(line.substr(12));
            if (!decoded || decoded->empty() ||
                decoded->size() > maximum_marker_size) {
                return std::nullopt;
            }
            record.payload = std::move(*decoded);
            seen_payload = true;
        } else {
            return std::nullopt;
        }
        if (nl == std::string_view::npos) {
            break;
        }
        rest = rest.substr(nl + 1);
    }
    if (!seen_kind || !seen_id || !seen_token || !seen_sha || !seen_payload ||
        (record.kind != "writer" && record.kind != "barrier") ||
        !is_canonical_hex32(record.token) ||
        !history::valid_commit_id(record.expected_physical_sha256) ||
        record.identifier.empty()) {
        return std::nullopt;
    }
    return record;
}

std::expected<void, Error>
persist_pending_record(const std::filesystem::path& pending_file,
                       std::string_view kind,
                       const RegistrationState& registration) {
    if (auto ensured = platform::private_storage::ensure_directory(
            pending_file.parent_path());
        !ensured) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, ensured.error()));
    }
    const auto serialized = serialize_pending_record(kind, registration);
    if (auto written =
            platform::private_storage::write_atomically(pending_file, serialized);
        !written) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, written.error()));
    }
    return {};
}

void remove_pending_record(const std::filesystem::path& pending_file) noexcept {
    if (pending_file.empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::remove(pending_file, ec);
    const auto dir = pending_file.parent_path();
    if (!dir.empty()) {
        std::error_code dir_ec;
        std::filesystem::remove(dir, dir_ec);
    }
}

std::expected<bool, Error>
registration_matches(transport::Transport& storage,
                     const RegistrationState& registration);

// Reconciles ownership before any deletion so an indeterminate control marker
// cleans up only our exact payload+hash and keeps local evidence on outage.
bool reconcile_and_cleanup_registration(
    transport::Transport& storage,
    RegistrationState& registration,
    const std::filesystem::path& pending_file) noexcept {
    try {
        const platform::cancellation::ScopedIgnoreCancellation ignore_cancel;
        auto matches = registration_matches(storage, registration);
        if (!matches) {
            return false;
        }
        if (*matches) {
            auto removed = transport::remove(storage, registration.identifier);
            if (!removed) {
                return false;
            }
        }
        remove_pending_record(pending_file);
        registration.storage = nullptr;
        return true;
    } catch (...) {
        return false;
    }
}

bool kind_matches_filter(std::string_view record_kind,
                         PendingRegistrationKind filter) noexcept {
    switch (filter) {
        case PendingRegistrationKind::All:
            return true;
        case PendingRegistrationKind::Writer:
            return record_kind == "writer";
        case PendingRegistrationKind::Barrier:
            return record_kind == "barrier";
    }
    return false;
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
    auto snapshot = read_control_snapshot(
        *registration.storage, layout, true, &registration.workspace_root);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    if (auto known = validate_known_controls(*snapshot, true); !known) {
        return std::unexpected(known.error());
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
                        const RemoteLayout& layout,
                        std::optional<GenesisAdmission> genesis) {
    if (!registration_active(registration) ||
        !valid_writer_identifier(layout, registration.identifier)) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid writer registration"));
    }
    auto owned = verify_registration(registration);
    if (!owned) {
        return std::unexpected(owned.error());
    }
    auto snapshot = read_control_snapshot(*registration.storage,
                                          layout,
                                          genesis.has_value(),
                                          &registration.workspace_root);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    if (auto known = validate_known_controls(*snapshot, genesis.has_value());
        !known) {
        return std::unexpected(known.error());
    }
    if (any_barrier_present(*snapshot)) {
        return std::unexpected(
            error(ErrorCode::Blocked, "GC active on destination"));
    }
    if (genesis) {
        if (snapshot->writers.size() != 1 ||
            snapshot->writers.front() != registration.token) {
            return std::unexpected(
                error(ErrorCode::Blocked,
                      "vault initialization requires a single visible writer; "
                      "retry after peers finish"));
        }
        // Read publication evidence AFTER establishing that our marker was
        // alone. A peer could have finished since the original observation.
        for (const auto& [prefix, expected] :
             {std::pair{layout.heads_prefix, genesis->expected_head},
              std::pair{layout.epochs_prefix, genesis->expected_epoch}}) {
            auto entries = list_children(*registration.storage, prefix);
            if (!entries)
                return std::unexpected(entries.error());
            if (entries->empty()) {
                if (prefix == layout.heads_prefix && !expected.empty()) {
                    return std::unexpected(error(
                        ErrorCode::Blocked,
                        "journaled genesis HEAD disappeared during recovery"));
                }
                continue;
            }
            if (entries->size() != 1 || prefix + entries->front() != expected) {
                return std::unexpected(
                    error(ErrorCode::Blocked,
                          "remote history changed during vault initialization; "
                          "reobserve before publication"));
            }
        }
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
    const platform::cancellation::ScopedIgnoreCancellation ignore_cancel;
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

std::expected<void, Error> reconcile_pending_registrations(
    transport::Transport& storage,
    const RemoteLayout& layout,
    const std::filesystem::path& workspace_root,
    PendingRegistrationKind kind) {
    if (!transport::valid(storage) || workspace_root.empty()) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid reconciliation context"));
    }
    const auto dir = pending_markers_directory(workspace_root);
    std::error_code ec;
    const auto dir_status = std::filesystem::symlink_status(dir, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        !std::filesystem::exists(dir_status)) {
        return {};
    }
    if (ec) {
        return std::unexpected(error(
            ErrorCode::WorkspaceFailure,
            "failed to inspect pending control markers: " + ec.message()));
    }
    if (!std::filesystem::is_directory(dir_status)) {
        return std::unexpected(error(
            ErrorCode::WorkspaceFailure,
            "pending control markers path is not a directory"));
    }

    std::vector<std::filesystem::path> files;
    for (std::filesystem::directory_iterator it(dir, ec), end; !ec && it != end;
         it.increment(ec)) {
        std::error_code entry_ec;
        if (it->is_regular_file(entry_ec)) {
            files.push_back(it->path());
        }
    }
    if (ec) {
        return std::unexpected(error(
            ErrorCode::WorkspaceFailure,
            "failed to enumerate pending control markers: " + ec.message()));
    }
    std::ranges::sort(files);

    for (const auto& file : files) {
        auto raw = detail::read_file(file, 4096U);
        if (!raw) {
            return std::unexpected(history_error(raw.error()));
        }
        auto parsed = parse_pending_record(*raw);
        if (!parsed) {
            return std::unexpected(
                error(ErrorCode::WorkspaceFailure,
                      "invalid pending control marker record: " +
                          platform::path::to_utf8(file.filename())));
        }
        if (!kind_matches_filter(parsed->kind, kind)) {
            continue;
        }
        const bool belongs_to_layout =
            parsed->kind == "writer"
                ? valid_writer_identifier(layout, parsed->identifier)
                : valid_barrier_identifier(layout, parsed->identifier);
        if (!belongs_to_layout) {
            continue;
        }
        if (is_pending_identifier_active(parsed->identifier)) {
            continue;
        }
        RegistrationState reg{
            .storage = &storage,
            .workspace_root = workspace_root,
            .identifier = parsed->identifier,
            .token = parsed->token,
            .payload = std::move(parsed->payload),
            .expected_physical_sha256 =
                std::move(parsed->expected_physical_sha256),
            .verify_owner = true,
        };
        auto matches = registration_matches(storage, reg);
        if (!matches) {
            auto err = matches.error();
            err.identifier = reg.identifier;
            return std::unexpected(std::move(err));
        }
        if (*matches) {
            const platform::cancellation::ScopedIgnoreCancellation
                ignore_cancel;
            auto removed = transport::remove(storage, reg.identifier);
            if (!removed) {
                auto err = transport_error(removed.error());
                err.identifier = reg.identifier;
                return std::unexpected(std::move(err));
            }
            auto present = transport::presence(storage, reg.identifier);
            if (!present) {
                auto err = transport_error(present.error());
                err.identifier = reg.identifier;
                return std::unexpected(std::move(err));
            }
            if (*present != transport::Presence::Absent) {
                return std::unexpected(error(
                    ErrorCode::VerificationFailure,
                    "abandoned control marker remains present after cleanup",
                    reg.identifier));
            }
        }
        remove_pending_record(file);
    }
    return {};
}

namespace {

struct PreparedPublication {
    RegistrationState registration;
    std::filesystem::path pending_file;
    bool put_succeeded = false;
};

enum class VerifyPublishOutcome {
    Verified,
    HashMismatch,
    TransportFailed,
    Cancelled,
};

std::expected<void, Error> publish_registered_marker(
    transport::Transport& storage,
    const std::filesystem::path& workspace_root,
    std::string_view kind,
    std::string_view name,
    std::string_view identifier,
    std::vector<std::uint8_t> bytes,
    bool verify_owner,
    RegistrationState& registration_out,
    std::filesystem::path& pending_file_out) {
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

    registration_out = RegistrationState{
        .storage = &storage,
        .workspace_root = workspace_root,
        .identifier = std::string{identifier},
        .token = std::string{name},
        .payload = bytes,
        .expected_physical_sha256 = *local_hash,
        .verify_owner = verify_owner,
    };
    pending_file_out = pending_marker_path(workspace_root, kind, name);
    if (auto persisted =
            persist_pending_record(pending_file_out, kind, registration_out);
        !persisted) {
        return std::unexpected(persisted.error());
    }

    auto sent = transport::put(storage, source, identifier);
    if (!sent) {
        auto err = transport_error(sent.error());
        err.identifier = registration_out.identifier;
        if (sent.error().code == transport::ErrorCode::Cancelled ||
            platform::cancellation::requested()) {
            reconcile_and_cleanup_registration(
                storage, registration_out, pending_file_out);
        }
        return std::unexpected(std::move(err));
    }

    auto handle_cancelled = [&](Error base_err) {
        base_err.identifier = registration_out.identifier;
        reconcile_and_cleanup_registration(
            storage, registration_out, pending_file_out);
        return std::unexpected(std::move(base_err));
    };

    auto remote_hash = transport::physical_hash(storage, identifier, "sha256");
    if (remote_hash) {
        if (platform::cancellation::requested()) {
            return handle_cancelled(error(ErrorCode::TransportFailure,
                                          "operation cancelled by user"));
        }
        if (*remote_hash != *local_hash) {
            remove_pending_record(pending_file_out);
            auto err =
                error(ErrorCode::VerificationFailure,
                      "remote physical hash does not match published marker",
                      registration_out.identifier);
            return std::unexpected(std::move(err));
        }
        return {};
    }
    if (remote_hash.error().code != transport::ErrorCode::Unsupported) {
        auto err = transport_error(remote_hash.error());
        err.identifier = registration_out.identifier;
        if (remote_hash.error().code == transport::ErrorCode::Cancelled ||
            platform::cancellation::requested()) {
            return handle_cancelled(std::move(err));
        }
        return std::unexpected(std::move(err));
    }

    if (auto downloaded = detail::download(storage, identifier, copy);
        !downloaded) {
        auto err = history_error(downloaded.error());
        err.identifier = registration_out.identifier;
        if (platform::cancellation::requested()) {
            return handle_cancelled(std::move(err));
        }
        return std::unexpected(std::move(err));
    }
    if (platform::cancellation::requested()) {
        return handle_cancelled(
            error(ErrorCode::TransportFailure, "operation cancelled by user"));
    }
    auto observed = detail::read_file(copy, maximum_marker_size);
    if (!observed) {
        auto err = history_error(observed.error());
        err.identifier = registration_out.identifier;
        return std::unexpected(std::move(err));
    }
    if (!std::ranges::equal(*observed, bytes)) {
        remove_pending_record(pending_file_out);
        return std::unexpected(
            error(ErrorCode::VerificationFailure,
                  "remote marker does not match published marker",
                  registration_out.identifier));
    }
    return {};
}

} // namespace

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
    if (auto reconciled = reconcile_pending_registrations(
            storage, layout, workspace_root, PendingRegistrationKind::Writer);
        !reconciled) {
        return std::unexpected(reconciled.error());
    }
    auto token = platform::random::hex_id();
    if (!token) {
        return std::unexpected(
            error(ErrorCode::WorkspaceFailure, token.error()));
    }
    const auto name = *token;
    const auto identifier = layout.writers_prefix + name;
    const ActivePendingGuard active_pending(identifier);
    auto bytes = payload("writer", *token, metadata);

    RegistrationState registration;
    std::filesystem::path pending_file;
    if (auto published = publish_registered_marker(storage,
                                                   workspace_root,
                                                   "writer",
                                                   name,
                                                   identifier,
                                                   std::move(bytes),
                                                   false,
                                                   registration,
                                                   pending_file);
        !published) {
        return std::unexpected(published.error());
    }
    const auto fail_releasing = [&](Error failure) {
        failure.identifier = registration.identifier;
        reconcile_and_cleanup_registration(storage, registration, pending_file);
        return std::unexpected(std::move(failure));
    };
    auto snapshot =
        read_control_snapshot(storage, layout, true, &workspace_root);
    if (!snapshot) {
        return fail_releasing(snapshot.error());
    }
    if (auto known = validate_known_controls(*snapshot, true); !known) {
        return fail_releasing(known.error());
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
    remove_pending_record(pending_file);
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
    if (auto reconciled = reconcile_pending_registrations(
            storage, layout, workspace_root, PendingRegistrationKind::All);
        !reconciled) {
        return std::unexpected(reconciled.error());
    }
    auto pre_check =
        read_control_snapshot(storage, layout, true, &workspace_root);
    if (!pre_check) {
        return std::unexpected(pre_check.error());
    }
    if (auto known = validate_known_controls(*pre_check, true); !known) {
        return std::unexpected(known.error());
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
    const ActivePendingGuard active_pending(identifier);
    const auto meta = options.metadata.value_or(default_metadata());
    auto bytes = payload("barrier", name, meta);

    RegistrationState registration;
    std::filesystem::path pending_file;
    if (auto published = publish_registered_marker(storage,
                                                   workspace_root,
                                                   "barrier",
                                                   name,
                                                   identifier,
                                                   std::move(bytes),
                                                   true,
                                                   registration,
                                                   pending_file);
        !published) {
        return std::unexpected(published.error());
    }
    if (options.settle_delay > std::chrono::milliseconds::zero()) {
        std::this_thread::sleep_for(options.settle_delay);
        if (platform::cancellation::requested()) {
            reconcile_and_cleanup_registration(
                storage, registration, pending_file);
            return std::unexpected(
                error(ErrorCode::TransportFailure,
                      "operation cancelled by user",
                      registration.identifier));
        }
    }
    auto exclusive =
        verify_barrier_exclusivity_impl(registration, layout, true);
    if (!exclusive) {
        auto err = exclusive.error();
        err.identifier = registration.identifier;
        reconcile_and_cleanup_registration(storage, registration, pending_file);
        return std::unexpected(std::move(err));
    }
    remove_pending_record(pending_file);
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
        auto kind = classify_control_entry(
            storage, layout.writers_prefix, name, "writer", nullptr);
        if (!kind) {
            return std::unexpected(kind.error());
        }
        if (*kind == ControlEntryKind::LegacyStagingResidue) {
            continue;
        }
        if (*kind == ControlEntryKind::Unknown) {
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
    if (auto known = validate_known_controls(*snapshot, false); !known) {
        return std::unexpected(known.error());
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

std::expected<void, Error> check_pre_barrier_controls(
    transport::Transport& storage,
    const RemoteLayout& layout,
    const std::filesystem::path& workspace_root) {
    const auto* root_ptr =
        workspace_root.empty() ? nullptr : &workspace_root;
    auto snapshot = read_control_snapshot(storage, layout, true, root_ptr);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    if (auto known = validate_known_controls(*snapshot, true); !known) {
        return std::unexpected(known.error());
    }
    if (any_barrier_present(*snapshot)) {
        return std::unexpected(
            error(ErrorCode::Blocked,
                  "another maintenance barrier is already present"));
    }
    if (!snapshot->writers.empty()) {
        std::string listing;
        for (std::size_t i = 0; i < snapshot->writers.size(); ++i) {
            if (i > 0) {
                listing.append(", ");
            }
            listing.append(layout.writers_prefix + snapshot->writers[i]);
        }
        return std::unexpected(error(
            ErrorCode::Blocked, "active writers block garbage collection: " + listing));
    }
    return {};
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

std::expected<WriterBatchRemovalResult, Error>
remove_writers(transport::Transport& storage,
               const RemoteLayout& layout,
               std::span<const std::string> identifiers,
               const std::function<void(std::size_t done,
                                          std::size_t total,
                                          std::string_view current)>& on_step) {
    if (!transport::valid(storage) || identifiers.empty()) {
        return std::unexpected(
            error(ErrorCode::InvalidInput, "invalid writer marker identifiers"));
    }

    std::vector<std::string> unique_ids;
    unique_ids.reserve(identifiers.size());
    std::unordered_set<std::string> seen;
    seen.reserve(identifiers.size());
    for (const auto& id : identifiers) {
        if (!valid_writer_identifier(layout, id)) {
            return std::unexpected(error(ErrorCode::InvalidInput,
                                         "invalid writer marker identifier"));
        }
        if (seen.insert(id).second) {
            unique_ids.push_back(id);
        }
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

    auto writers = active_writers(storage, layout);
    if (!writers) {
        return std::unexpected(writers.error());
    }
    std::unordered_set<std::string> listed(writers->begin(), writers->end());

    WriterBatchRemovalResult result;
    const auto total = unique_ids.size();
    for (std::size_t index = 0; index < total; ++index) {
        if (platform::cancellation::requested()) {
            return std::unexpected(error(ErrorCode::TransportFailure,
                                         "operation cancelled by user"));
        }
        const auto& id = unique_ids[index];
        if (on_step) {
            on_step(index, total, id);
        }
        if (!listed.contains(id)) {
            result.already_absent.push_back(id);
            continue;
        }
        auto present = transport::presence(storage, id);
        if (!present) {
            return std::unexpected(transport_error(present.error()));
        }
        if (*present != transport::Presence::Present) {
            result.already_absent.push_back(id);
            continue;
        }
        auto removed = transport::remove(storage, id);
        if (!removed) {
            return std::unexpected(transport_error(removed.error()));
        }
        if (*removed != transport::Removal::Removed) {
            result.already_absent.push_back(id);
            continue;
        }
        present = transport::presence(storage, id);
        if (!present) {
            return std::unexpected(transport_error(present.error()));
        }
        if (*present != transport::Presence::Absent) {
            return std::unexpected(
                error(ErrorCode::VerificationFailure,
                      "writer marker remains after removal"));
        }
        result.removed.push_back(id);
    }
    if (on_step) {
        on_step(total, total, {});
    }

    if (!result.removed.empty()) {
        writers = active_writers(storage, layout);
        if (!writers) {
            return std::unexpected(writers.error());
        }
        const std::unordered_set<std::string> removed_set(result.removed.begin(),
                                                          result.removed.end());
        for (const auto& remaining : *writers) {
            if (removed_set.contains(remaining)) {
                return std::unexpected(
                    error(ErrorCode::VerificationFailure,
                          "writer marker remains listed"));
            }
        }
    }
    return result;
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
    std::vector<std::string> legacy_staging_barriers;
    if (*legacy_present == transport::Presence::Present) {
        present_barriers.push_back(layout.barrier_identifier);
    }
    for (const auto& name : *multi_barriers) {
        auto kind = classify_control_entry(
            storage, layout.barriers_prefix, name, "barrier", &workspace_root);
        if (!kind) {
            return with_context(BarrierRemovalStage::CheckingPresence,
                                kind.error());
        }
        if (*kind == ControlEntryKind::PublishedMarker) {
            present_barriers.push_back(layout.barriers_prefix + name);
        } else if (*kind == ControlEntryKind::LegacyStagingResidue) {
            legacy_staging_barriers.push_back(layout.barriers_prefix + name);
        } else {
            return fail(BarrierRemovalStage::CheckingPresence,
                        ErrorCode::InvalidControlObject,
                        "invalid barrier marker: " + name);
        }
    }

    std::size_t remaining_barriers = 0;
    if (target_barrier.has_value()) {
        std::string canonical;
        const auto legacy_staging_match = std::ranges::find_if(
            legacy_staging_barriers, [&](const std::string& id) {
                return *target_barrier == id ||
                       *target_barrier ==
                           std::string_view{id}.substr(
                               layout.barriers_prefix.size());
            });
        if (*target_barrier == layout.barrier_identifier ||
            *target_barrier == "barrier") {
            canonical = layout.barrier_identifier;
        } else if (valid_barrier_identifier(layout, *target_barrier)) {
            canonical = std::string{*target_barrier};
        } else if (is_canonical_hex32(*target_barrier)) {
            canonical = layout.barriers_prefix + std::string{*target_barrier};
        } else if (legacy_staging_match != legacy_staging_barriers.end()) {
            canonical = *legacy_staging_match;
        } else {
            active_identifier = std::string{*target_barrier};
            return fail(BarrierRemovalStage::CheckingPresence,
                        ErrorCode::InvalidInput,
                        "invalid maintenance barrier identifier or token");
        }
        active_identifier = canonical;
        if (present_barriers.empty() && legacy_staging_barriers.empty()) {
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
        if (std::ranges::find(present_barriers, canonical) !=
            present_barriers.end()) {
            remaining_barriers = present_barriers.size() - 1;
        } else if (std::ranges::find(legacy_staging_barriers, canonical) !=
                   legacy_staging_barriers.end()) {
            remaining_barriers = present_barriers.size();
        } else {
            return fail(BarrierRemovalStage::CheckingPresence,
                        ErrorCode::InvalidInput,
                        "specified maintenance barrier is not active");
        }
    } else {
        const auto& auto_pool = !present_barriers.empty()
                                    ? present_barriers
                                    : legacy_staging_barriers;
        if (auto_pool.empty()) {
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
        if (auto_pool.size() > 1) {
            std::string listing;
            for (std::size_t i = 0; i < auto_pool.size(); ++i) {
                if (i > 0) {
                    listing.append(", ");
                }
                listing.append(auto_pool[i]);
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
        active_identifier = auto_pool.front();
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
        const auto suffix = std::string_view{active_identifier}.substr(
            layout.barriers_prefix.size());
        if (const auto legacy_token = parse_legacy_local_staging_name(suffix)) {
            expected_token = *legacy_token;
        } else {
            expected_token = suffix;
        }
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
        const platform::cancellation::ScopedIgnoreCancellation ignore_cancel;
        auto probe_matches =
            verify_remote_payload(storage, identifier, bytes, workspace_root, "");
        if (probe_matches && *probe_matches) {
            static_cast<void>(transport::remove(storage, identifier));
        }
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
