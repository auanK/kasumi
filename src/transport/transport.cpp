#include "transport/transport.hpp"

#include "detail.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_set>
#include <utility>
#include <variant>

namespace kasumi::transport {

namespace {

using detail::make_error;

bool forbidden_character(char character) noexcept {
    const auto byte = static_cast<unsigned char>(character);
    return byte <= 0x1fU || byte == 0x7fU;
}

bool outer_whitespace(std::string_view value) noexcept {
    return !value.empty() &&
           (std::isspace(static_cast<unsigned char>(value.front())) != 0 ||
            std::isspace(static_cast<unsigned char>(value.back())) != 0);
}

bool windows_drive_path(std::string_view location) noexcept {
    return location.size() >= 3 &&
           std::isalpha(static_cast<unsigned char>(location[0])) != 0 &&
           location[1] == ':' && (location[2] == '/' || location[2] == '\\');
}

bool valid_remote_name(std::string_view name) noexcept {
    return !name.empty() && name != "." && name != ".." &&
           name.find_first_of(":/\\") == std::string_view::npos &&
           !outer_whitespace(name) &&
           std::none_of(name.begin(), name.end(), forbidden_character);
}

bool valid_remote_root(std::string_view root) noexcept {
    if (root.empty() || root.front() == '/' || root.front() == '\\' ||
        root.back() == '/' || root.find('\\') != std::string_view::npos ||
        std::any_of(root.begin(), root.end(), forbidden_character)) {
        return false;
    }

    std::size_t begin = 0;
    while (begin <= root.size()) {
        const auto end = root.find('/', begin);
        const auto component = root.substr(
            begin,
            end == std::string_view::npos ? root.size() - begin : end - begin);
        if (component.empty() || component == "." || component == "..") {
            return false;
        }
        if (end == std::string_view::npos) {
            break;
        }
        begin = end + 1;
    }
    return true;
}

std::expected<void, Error> validate_location_text(std::string_view location) {
    if (location.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext, "storage location is empty"));
    }
    if (std::any_of(location.begin(), location.end(), forbidden_character)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "storage location contains invalid characters"));
    }
    if (outer_whitespace(location)) {
        return std::unexpected(make_error(ErrorCode::InvalidContext,
                                          "storage location cannot begin or "
                                          "end with whitespace"));
    }
    return {};
}

Error invalid_transport_error() {
    return make_error(ErrorCode::InvalidContext,
                      "incomplete transport operations table");
}

bool valid_storage_operations(const StorageOperations& operations) noexcept {
    return operations.initialize != nullptr && operations.put != nullptr &&
           operations.get != nullptr && operations.presence != nullptr &&
           operations.list != nullptr && operations.remove != nullptr;
}

using BackendConfiguration =
    std::variant<detail::LocalConfiguration, detail::RcloneConfiguration>;

std::expected<BackendConfiguration, Error> parse_backend_configuration(
    std::string_view location,
    const std::filesystem::path& forbidden_executable_root = {}) {
    if (const auto valid_text = validate_location_text(location); !valid_text) {
        return std::unexpected(valid_text.error());
    }

    if (windows_drive_path(location) || location.starts_with("\\\\") ||
        location.find(':') == std::string_view::npos) {
        const auto root = platform::path::from_utf8(location);
        if (!root.is_absolute()) {
            return std::unexpected(
                make_error(ErrorCode::InvalidContext,
                           "local destination must use an absolute path"));
        }
        return detail::LocalConfiguration{
            .root = root,
        };
    }

    const auto separator = location.find(':');
    const auto remote_name = location.substr(0, separator);
    const auto remote_root = location.substr(separator + 1);
    if (!valid_remote_name(remote_name)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidIdentifier,
                       "only previously configured remotes are permitted"));
    }
    if (!valid_remote_root(remote_root)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidIdentifier, "remote root is invalid"));
    }

    return detail::RcloneConfiguration{
        .remote_name = std::string{remote_name},
        .remote_root = std::string{remote_root},
        .executable = std::filesystem::path{"rclone"},
        .config_path = std::nullopt,
        .forbidden_executable_root = forbidden_executable_root,
    };
}

void* state_pointer(Transport& transport) noexcept {
    return transport.state.get();
}

std::expected<Transport, Error> accept_backend_transport(Transport transport) {
    if (!valid(transport)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "backend returned an incomplete transport"));
    }
    return transport;
}

template <typename Range, typename Proj>
std::expected<std::unordered_set<std::string>, Error>
validate_unique_identifiers(const Range& items,
                            Proj proj,
                            std::string_view error_message,
                            bool check_forbidden = false) {
    std::unordered_set<std::string> seen;
    for (const auto& item : items) {
        const auto& id = proj(item);
        if (!detail::valid_relative_identifier(id, true) ||
            (check_forbidden && std::ranges::any_of(id, forbidden_character)) ||
            !seen.insert(std::string{id}).second) {
            return std::unexpected(make_error(ErrorCode::InvalidIdentifier,
                                              std::string{error_message}));
        }
    }
    return seen;
}

std::expected<void, Error> validate_batch(const PutBatch& batch) {
    std::error_code error;
    if (!std::filesystem::is_directory(batch.source_root, error)) {
        return std::unexpected(make_error(
            ErrorCode::InvalidContext, "source_root is not a valid directory"));
    }
    if (std::filesystem::is_symlink(batch.source_root, error)) {
        return std::unexpected(make_error(ErrorCode::InvalidContext,
                                          "source_root cannot be a symlink"));
    }

    const auto unique_identifiers = validate_unique_identifiers(
        batch.identifiers,
        [](const std::string& id) -> const std::string& {
            return id;
        },
        "duplicate or invalid identifier in batch");
    if (!unique_identifiers) {
        return std::unexpected(unique_identifiers.error());
    }
    for (const auto& identifier : batch.identifiers) {
        auto path = batch.source_root / platform::path::from_utf8(identifier);
        if (std::filesystem::is_symlink(path, error)) {
            return std::unexpected(make_error(
                ErrorCode::InvalidContext, "batch files cannot be symlinks"));
        }
        if (!std::filesystem::is_regular_file(path, error)) {
            return std::unexpected(
                make_error(ErrorCode::ObjectNotFound,
                           "batch file does not exist or is not regular"));
        }
    }

    auto iterator = std::filesystem::recursive_directory_iterator(
        batch.source_root, std::filesystem::directory_options::none, error);
    if (error) {
        return std::unexpected(
            make_error(ErrorCode::Io, "failed to access source_root"));
    }

    for (const std::filesystem::recursive_directory_iterator end;
         iterator != end;
         iterator.increment(error)) {
        if (error) {
            return std::unexpected(
                make_error(ErrorCode::Io, "failed to iterate source_root"));
        }
        if (iterator->is_symlink(error)) {
            return std::unexpected(make_error(ErrorCode::InvalidContext,
                                              "symlinks found in staging"));
        }
        if (iterator->is_regular_file(error)) {
            auto relative = std::filesystem::relative(
                iterator->path(), batch.source_root, error);
            if (error) {
                return std::unexpected(
                    make_error(ErrorCode::Io,
                               "failed to compute relative path in staging"));
            }
            if (!unique_identifiers->contains(
                    platform::path::to_logical_utf8(relative))) {
                return std::unexpected(make_error(
                    ErrorCode::InvalidContext,
                    "staging contains files not specified in manifest"));
            }
        }
    }

    return {};
}

std::expected<void, Error> validate_remove_batch(const RemoveBatch& batch) {
    if (batch.items.empty()) {
        return {};
    }
    if (batch.concurrency == 0) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "remove batch concurrency must be positive"));
    }
    const auto ids = validate_unique_identifiers(
        batch.items,
        [](const RemoveBatchItem& item) -> const std::string& {
            return item.identifier;
        },
        "invalid or duplicate remove batch identifier",
        true);
    return ids ? std::expected<void, Error>{} : std::unexpected(ids.error());
}

std::expected<void, Error> validate_batch(const GetBatch& batch) {
    std::error_code error;
    if (!batch.source_prefix.empty() &&
        !detail::valid_relative_identifier(batch.source_prefix, true)) {
        return std::unexpected(make_error(ErrorCode::InvalidIdentifier,
                                          "invalid prefix in batch"));
    }
    if (!std::filesystem::is_directory(batch.destination_root, error) ||
        std::filesystem::is_symlink(batch.destination_root, error)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "destination_root is not a valid directory"));
    }
    const auto ids = validate_unique_identifiers(
        batch.identifiers,
        [](const std::string& id) -> const std::string& {
            return id;
        },
        "duplicate or invalid identifier in batch");
    return ids ? std::expected<void, Error>{} : std::unexpected(ids.error());
}

std::expected<void, Error>
validate_physical_hash_batch_request(const PhysicalHashBatchRequest& request) {
    if (request.scratch_root.empty() || request.algorithm.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "incomplete batch physical hash request"));
    }
    if (request.objects.empty()) {
        return std::unexpected(make_error(ErrorCode::InvalidIdentifier,
                                          "empty batch physical hash request"));
    }

    std::unordered_set<std::string> identifiers;
    for (const auto& object : request.objects) {
        if (!detail::valid_relative_identifier(object.identifier, true) ||
            object.identifier.find_first_of("\r\n") != std::string_view::npos) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "invalid identifier in physical hash request"));
        }
        if (object.expected_hash.empty()) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "empty expected hash in physical hash request"));
        }
        if (!identifiers.insert(object.identifier).second) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "duplicate identifiers in physical hash request"));
        }
    }
    return {};
}

std::expected<void, Error>
validate_physical_hash_batch_report(const PhysicalHashBatchReport& report,
                                    const PhysicalHashBatchRequest& request) {
    std::unordered_set<std::string> requested;
    requested.reserve(request.objects.size());
    for (const auto& object : request.objects) {
        requested.insert(object.identifier);
    }

    std::unordered_set<std::string> seen;
    seen.reserve(request.objects.size());

    const std::vector<const std::vector<std::string>*> categories = {
        &report.matched, &report.mismatched, &report.missing, &report.errors};

    for (const auto* list : categories) {
        for (const auto& identifier : *list) {
            if (identifier.empty() ||
                identifier.find_first_of("\r\n") != std::string_view::npos) {
                return std::unexpected(make_error(
                    ErrorCode::ProtocolFailure,
                    "invalid identifier in physical hash batch report"));
            }
            if (!requested.contains(identifier)) {
                return std::unexpected(make_error(
                    ErrorCode::ProtocolFailure,
                    "unexpected identifier in physical hash batch report: " +
                        identifier));
            }
            if (!seen.insert(identifier).second) {
                return std::unexpected(make_error(
                    ErrorCode::ProtocolFailure,
                    "duplicate identifier in physical hash batch report: " +
                        identifier));
            }
        }
    }

    if (seen.size() != requested.size()) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure,
            "incomplete physical hash batch report: expected " +
                std::to_string(requested.size()) + " objects, but classified " +
                std::to_string(seen.size())));
    }

    return {};
}

std::expected<void, Error>
validate_control_read_batch_request(const ControlReadBatchRequest& request) {
    if (request.list_prefixes.empty() && request.presence_identifiers.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext, "empty control read batch"));
    }
    const auto prefixes = validate_unique_identifiers(
        request.list_prefixes,
        [](const std::string& p) -> const std::string& {
            return p;
        },
        "duplicate or invalid prefix in control batch");
    if (!prefixes) {
        return std::unexpected(prefixes.error());
    }
    const auto ids = validate_unique_identifiers(
        request.presence_identifiers,
        [](const std::string& id) -> const std::string& {
            return id;
        },
        "duplicate or invalid identifier in control batch");
    return ids ? std::expected<void, Error>{} : std::unexpected(ids.error());
}

template <typename Fn, typename... Args>
auto call_required(Transport& transport, Fn fn, Args&&... args)
    -> decltype(fn(state_pointer(transport), std::forward<Args>(args)...)) {
    auto* state = state_pointer(transport);
    if (state == nullptr || fn == nullptr) {
        return std::unexpected(invalid_transport_error());
    }
    return fn(state, std::forward<Args>(args)...);
}

template <typename Fn, typename... Args>
auto call_optional(Transport& transport,
                   Fn fn,
                   std::string_view unsupported_message,
                   Args&&... args)
    -> decltype(fn(state_pointer(transport), std::forward<Args>(args)...)) {
    auto* state = state_pointer(transport);
    if (state == nullptr) {
        return std::unexpected(invalid_transport_error());
    }
    if (fn == nullptr) {
        return std::unexpected(make_error(ErrorCode::Unsupported,
                                          std::string{unsupported_message}));
    }
    return fn(state, std::forward<Args>(args)...);
}

} // namespace

Result validate_transport_location(std::string_view location) {
    const auto configuration = parse_backend_configuration(location);
    if (!configuration) {
        return std::unexpected(configuration.error());
    }
    return {};
}

std::expected<Transport, Error>
open_transport(std::string_view location,
               const std::filesystem::path& forbidden_executable_root) {
    const auto configuration =
        parse_backend_configuration(location, forbidden_executable_root);
    if (!configuration) {
        return std::unexpected(configuration.error());
    }

    auto transport =
        std::holds_alternative<detail::LocalConfiguration>(*configuration)
            ? detail::open_local_backend(
                  std::get<detail::LocalConfiguration>(*configuration))
            : detail::open_rclone_backend(
                  std::get<detail::RcloneConfiguration>(*configuration));
    if (!transport) {
        return std::unexpected(transport.error());
    }
    return accept_backend_transport(std::move(*transport));
}

bool valid(const Transport& transport) noexcept {
    return transport.state.get() != nullptr &&
           transport.state.get_deleter() != nullptr &&
           valid_storage_operations(transport.storage);
}

Result initialize(Transport& transport) {
    return call_required(transport, transport.storage.initialize);
}

Result put(Transport& transport,
           const std::filesystem::path& source,
           std::string_view identifier) {
    return call_required(transport, transport.storage.put, source, identifier);
}

Result put_batch(Transport& transport, const PutBatch& batch) {
    if (auto v = validate_batch(batch); !v) {
        return v;
    }
    if (batch.identifiers.empty()) {
        return {};
    }
    auto* state = state_pointer(transport);
    if (state == nullptr) {
        return std::unexpected(invalid_transport_error());
    }
    if (transport.storage.put_batch != nullptr) {
        return transport.storage.put_batch(state, batch);
    }
    for (const auto& identifier : batch.identifiers) {
        if (auto res =
                put(transport,
                    batch.source_root / platform::path::from_utf8(identifier),
                    identifier);
            !res) {
            return res;
        }
    }
    return {};
}

Result get(Transport& transport,
           std::string_view identifier,
           const std::filesystem::path& destination) {
    return call_required(
        transport, transport.storage.get, identifier, destination);
}

Result get_batch(Transport& transport, const GetBatch& batch) {
    if (auto v = validate_batch(batch); !v) {
        return v;
    }
    if (batch.identifiers.empty()) {
        return {};
    }
    auto* state = state_pointer(transport);
    if (state == nullptr) {
        return std::unexpected(invalid_transport_error());
    }
    if (transport.storage.get_batch != nullptr) {
        return transport.storage.get_batch(state, batch);
    }
    for (const auto& identifier : batch.identifiers) {
        const auto source = batch.source_prefix.empty()
                                ? identifier
                                : batch.source_prefix + "/" + identifier;
        if (auto res = get(transport,
                           source,
                           batch.destination_root /
                               platform::path::from_utf8(identifier));
            !res) {
            return res;
        }
    }
    return {};
}

PresenceResult presence(Transport& transport, std::string_view identifier) {
    return call_required(transport, transport.storage.presence, identifier);
}

ListingResult list(Transport& transport) {
    return call_required(transport, transport.storage.list);
}

ListingResult list(Transport& transport, std::string_view prefix) {
    if (!detail::valid_relative_identifier(prefix, true)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidIdentifier, "invalid listing prefix"));
    }
    return call_required(transport, transport.storage.list_prefix, prefix);
}

std::expected<std::string, Error> physical_hash(Transport& transport,
                                                std::string_view identifier,
                                                std::string_view algorithm) {
    return call_optional(transport,
                         transport.storage.physical_hash,
                         "transport does not support remote physical hash",
                         identifier,
                         algorithm);
}

PhysicalHashBatchResult
physical_hash_batch(Transport& transport,
                    const PhysicalHashBatchRequest& request) {
    if (!valid(transport)) {
        return std::unexpected(invalid_transport_error());
    }
    if (auto v = validate_physical_hash_batch_request(request); !v) {
        return std::unexpected(v.error());
    }
    auto result =
        call_optional(transport,
                      transport.storage.physical_hash_batch,
                      "transport does not support batch remote physical hash",
                      request);
    if (!result) {
        return result;
    }
    if (auto v = validate_physical_hash_batch_report(*result, request); !v) {
        return std::unexpected(v.error());
    }
    return result;
}

bool prefers_physical_hash_batch(const Transport& transport,
                                 std::size_t object_count) noexcept {
    return valid(transport) &&
           transport.storage.physical_hash_batch != nullptr &&
           transport.storage.physical_hash_batch_min_objects != 0 &&
           object_count >= transport.storage.physical_hash_batch_min_objects;
}

ControlReadBatchResponse
control_read_batch(Transport& transport,
                   const ControlReadBatchRequest& request) {
    if (!valid(transport)) {
        return std::unexpected(invalid_transport_error());
    }
    if (auto v = validate_control_read_batch_request(request); !v) {
        return std::unexpected(v.error());
    }
    return call_optional(transport,
                         transport.storage.control_read_batch,
                         "transport does not support control read batch",
                         request);
}

RemovalResult remove(Transport& transport, std::string_view identifier) {
    // A removal failure is ambiguous: the backend may have applied the effect
    // before reporting an error. Do not probe and reinterpret it as success,
    // because callers must stop on uncertain mutation. Exactly one REMOVE
    // attempt is made and the original error (including native_code) is kept.
    return call_required(transport, transport.storage.remove, identifier);
}

RemoveBatchResult remove_batch(Transport& transport, const RemoveBatch& batch) {
    if (auto v = validate_remove_batch(batch); !v) {
        return std::unexpected(v.error());
    }
    if (batch.items.empty()) {
        return RemoveBatchReport{};
    }
    return call_optional(transport,
                         transport.storage.remove_batch,
                         "transport does not support explicit remove batch",
                         batch);
}

namespace detail {

bool valid_relative_identifier(std::string_view identifier,
                               bool require_normal) noexcept {
    if (identifier.empty() || identifier.find('\\') != std::string_view::npos ||
        std::any_of(
            identifier.begin(), identifier.end(), forbidden_character)) {
        return false;
    }
    const auto path = platform::path::from_utf8(identifier);
    if (path.empty() || path.is_absolute() || path.has_root_name() ||
        path.has_root_directory()) {
        return false;
    }
    for (const auto& component : path) {
        if (component == "." || component == "..") {
            return false;
        }
    }
    const auto normalized = path.lexically_normal();
    if (require_normal) {
        return normalized == path;
    }
    return !normalized.empty() && normalized != "." &&
           !normalized.is_absolute() && !normalized.has_root_name() &&
           !normalized.has_root_directory();
}

} // namespace detail

} // namespace kasumi::transport
