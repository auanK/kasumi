#include "transport/transport.hpp"

#include "detail.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_set>
#include <utility>
#include <variant>

namespace kasumi::transport {

namespace {

Error make_error(ErrorCode code, std::string message) {
    return Error{.code = code, .message = std::move(message), .native_code = 0};
}

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
            make_error(ErrorCode::InvalidContext,
                       "localização do armazenamento está vazia"));
    }
    if (std::any_of(location.begin(), location.end(), forbidden_character)) {
        return std::unexpected(make_error(
            ErrorCode::InvalidContext,
            "localização do armazenamento contém caracteres inválidos"));
    }
    if (outer_whitespace(location)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "localização do armazenamento não pode começar ou "
                       "terminar com whitespace"));
    }
    return {};
}

Error invalid_transport_error() {
    return Error{
        .code = ErrorCode::InvalidContext,
        .message = "tabela de operações de transporte incompleta",
        .native_code = 0,
    };
}

bool valid_storage_operations(const StorageOperations& operations) noexcept {
    return operations.initialize != nullptr && operations.put != nullptr &&
           operations.get != nullptr && operations.presence != nullptr &&
           operations.list != nullptr && operations.remove != nullptr;
}

bool valid_list_prefix(std::string_view prefix) noexcept {
    if (prefix.empty() || prefix.find('\\') != std::string_view::npos) {
        return false;
    }
    const auto path = platform::path::from_utf8(prefix);
    if (path.is_absolute() || path.has_root_name() ||
        path.has_root_directory()) {
        return false;
    }
    for (const auto& component : path) {
        if (component == "." || component == "..") {
            return false;
        }
    }
    return path.lexically_normal() == path;
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
                           "o destino local deve usar um caminho absoluto"));
        }
        return detail::LocalConfiguration{
            .root = root,
        };
    }

    const auto separator = location.find(':');
    const auto remote_name = location.substr(0, separator);
    const auto remote_root = location.substr(separator + 1);
    if (!valid_remote_name(remote_name)) {
        return std::unexpected(make_error(
            ErrorCode::InvalidIdentifier,
            "somente remotes previamente configurados são permitidos"));
    }
    if (!valid_remote_root(remote_root)) {
        return std::unexpected(make_error(ErrorCode::InvalidIdentifier,
                                          "a raiz remota é inválida"));
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
                       "backend retornou um transporte incompleto"));
    }
    return transport;
}

bool valid_batch_identifier(std::string_view identifier) noexcept {
    if (identifier.empty() || identifier.find('\\') != std::string_view::npos) {
        return false;
    }
    const auto path = platform::path::from_utf8(identifier);
    if (path.is_absolute() || path.has_root_name() ||
        path.has_root_directory()) {
        return false;
    }
    for (const auto& component : path) {
        if (component == "." || component == "..") {
            return false;
        }
    }
    return path.lexically_normal() == path;
}

std::expected<void, Error> validate_batch(const PutBatch& batch) {
    std::error_code error;
    if (!std::filesystem::is_directory(batch.source_root, error)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "source_root não é um diretório válido"));
    }
    if (std::filesystem::is_symlink(batch.source_root, error)) {
        return std::unexpected(make_error(ErrorCode::InvalidContext,
                                          "source_root não pode ser symlink"));
    }

    std::unordered_set<std::string> unique_identifiers;
    for (const auto& identifier : batch.identifiers) {
        if (!valid_batch_identifier(identifier)) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "identificador inválido no batch"));
        }
        if (!unique_identifiers.insert(identifier).second) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "identificadores duplicados no batch"));
        }

        auto path = batch.source_root / platform::path::from_utf8(identifier);
        if (std::filesystem::is_symlink(path, error)) {
            return std::unexpected(
                make_error(ErrorCode::InvalidContext,
                           "arquivos do batch não podem ser symlinks"));
        }
        if (!std::filesystem::is_regular_file(path, error)) {
            return std::unexpected(
                make_error(ErrorCode::ObjectNotFound,
                           "arquivo do batch não existe ou não é regular"));
        }
    }

    auto iterator = std::filesystem::recursive_directory_iterator(
        batch.source_root, std::filesystem::directory_options::none, error);
    if (error) {
        return std::unexpected(
            make_error(ErrorCode::Io, "falha ao acessar source_root"));
    }

    const std::filesystem::recursive_directory_iterator end;
    for (; iterator != end; iterator.increment(error)) {
        if (error) {
            return std::unexpected(
                make_error(ErrorCode::Io, "falha ao iterar source_root"));
        }
        if (iterator->is_symlink(error)) {
            return std::unexpected(make_error(
                ErrorCode::InvalidContext, "symlinks encontrados no staging"));
        }
        if (iterator->is_regular_file(error)) {
            auto relative = std::filesystem::relative(
                iterator->path(), batch.source_root, error);
            if (error) {
                return std::unexpected(make_error(
                    ErrorCode::Io,
                    "falha ao calcular caminho relativo no staging"));
            }
            if (!unique_identifiers.contains(
                    platform::path::to_logical_utf8(relative))) {
                return std::unexpected(make_error(
                    ErrorCode::InvalidContext,
                    "staging contém arquivos não especificados no manifest"));
            }
        }
    }

    return {};
}

std::expected<void, Error> validate_batch(const GetBatch& batch) {
    std::error_code error;
    if (!batch.source_prefix.empty() &&
        !valid_list_prefix(batch.source_prefix)) {
        return std::unexpected(make_error(ErrorCode::InvalidIdentifier,
                                          "prefixo inválido no batch"));
    }
    if (!std::filesystem::is_directory(batch.destination_root, error) ||
        std::filesystem::is_symlink(batch.destination_root, error)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "destination_root não é um diretório válido"));
    }

    std::unordered_set<std::string> unique_identifiers;
    for (const auto& identifier : batch.identifiers) {
        if (!valid_batch_identifier(identifier) ||
            !unique_identifiers.insert(identifier).second) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "identificador duplicado ou inválido no batch"));
        }
    }
    return {};
}

std::expected<void, Error>
validate_physical_hash_batch_request(const PhysicalHashBatchRequest& request) {
    if (request.scratch_root.empty() || request.algorithm.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "requisição de hash físico em lote incompleta"));
    }
    if (request.objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidIdentifier,
                       "requisição de hash físico em lote vazia"));
    }

    std::unordered_set<std::string> identifiers;
    for (const auto& object : request.objects) {
        if (!valid_batch_identifier(object.identifier) ||
            object.identifier.find_first_of("\r\n") != std::string_view::npos) {
            return std::unexpected(make_error(
                ErrorCode::InvalidIdentifier,
                "identificador inválido na requisição de hash físico"));
        }
        if (object.expected_hash.empty()) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "hash esperado vazio na requisição de hash físico"));
        }
        if (!identifiers.insert(object.identifier).second) {
            return std::unexpected(make_error(
                ErrorCode::InvalidIdentifier,
                "identificadores duplicados na requisição de hash físico"));
        }
    }
    return {};
}

std::expected<void, Error>
validate_control_read_batch_request(const ControlReadBatchRequest& request) {
    if (request.list_prefixes.empty() && request.presence_identifiers.empty()) {
        return std::unexpected(make_error(
            ErrorCode::InvalidContext, "batch de leituras de controle vazio"));
    }
    std::unordered_set<std::string> prefixes;
    for (const auto& prefix : request.list_prefixes) {
        if (!valid_list_prefix(prefix) || !prefixes.insert(prefix).second) {
            return std::unexpected(make_error(
                ErrorCode::InvalidIdentifier,
                "prefixo duplicado ou inválido no batch de controle"));
        }
    }
    std::unordered_set<std::string> identifiers;
    for (const auto& identifier : request.presence_identifiers) {
        if (!valid_batch_identifier(identifier) ||
            !identifiers.insert(identifier).second) {
            return std::unexpected(make_error(
                ErrorCode::InvalidIdentifier,
                "identificador duplicado ou inválido no batch de controle"));
        }
    }
    return {};
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

    if (const auto* local =
            std::get_if<detail::LocalConfiguration>(&*configuration)) {
        auto transport = detail::open_local_backend(*local);
        if (!transport) {
            return std::unexpected(transport.error());
        }
        return accept_backend_transport(std::move(*transport));
    }

    if (const auto* rclone =
            std::get_if<detail::RcloneConfiguration>(&*configuration)) {
        auto transport = detail::open_rclone_backend(*rclone);
        if (!transport) {
            return std::unexpected(transport.error());
        }
        return accept_backend_transport(std::move(*transport));
    }

    return std::unexpected(
        make_error(ErrorCode::InvalidContext, "backend não reconhecido"));
}

bool valid(const Transport& transport) noexcept {
    return transport.state.get() != nullptr &&
           transport.state.get_deleter() != nullptr &&
           valid_storage_operations(transport.storage);
}

Result initialize(Transport& transport) {
    const auto trace = platform::perf_trace::begin();
    auto* state = state_pointer(transport);
    if (state == nullptr || transport.storage.initialize == nullptr) {
        platform::perf_trace::finish("transport initialize", trace);
        return std::unexpected(invalid_transport_error());
    }
    auto result = transport.storage.initialize(state);
    platform::perf_trace::finish("transport initialize", trace);
    return result;
}

Result put(Transport& transport,
           const std::filesystem::path& source,
           std::string_view identifier) {
    auto* state = state_pointer(transport);
    if (state == nullptr || transport.storage.put == nullptr) {
        return std::unexpected(invalid_transport_error());
    }

    return transport.storage.put(state, source, identifier);
}

Result put_batch(Transport& transport, const PutBatch& batch) {
    auto validation = validate_batch(batch);
    if (!validation) {
        return std::unexpected(validation.error());
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
        auto result = put(transport,
                          batch.source_root /
                              platform::path::from_utf8(identifier),
                          identifier);
        if (!result) {
            return result;
        }
    }

    return {};
}

Result get(Transport& transport,
           std::string_view identifier,
           const std::filesystem::path& destination) {
    auto* state = state_pointer(transport);
    if (state == nullptr || transport.storage.get == nullptr) {
        return std::unexpected(invalid_transport_error());
    }

    return transport.storage.get(state, identifier, destination);
}

Result get_batch(Transport& transport, const GetBatch& batch) {
    auto validation = validate_batch(batch);
    if (!validation) {
        return std::unexpected(validation.error());
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
        auto result = get(transport,
                          source,
                          batch.destination_root /
                              platform::path::from_utf8(identifier));
        if (!result) {
            return result;
        }
    }
    return {};
}

PresenceResult presence(Transport& transport, std::string_view identifier) {
    auto* state = state_pointer(transport);
    if (state == nullptr || transport.storage.presence == nullptr) {
        return std::unexpected(invalid_transport_error());
    }

    return transport.storage.presence(state, identifier);
}

ListingResult list(Transport& transport) {
    auto* state = state_pointer(transport);
    if (state == nullptr || transport.storage.list == nullptr) {
        return std::unexpected(invalid_transport_error());
    }

    platform::perf_trace::count("transport list");
    return transport.storage.list(state);
}

ListingResult list(Transport& transport, std::string_view prefix) {
    auto* state = state_pointer(transport);
    if (state == nullptr || transport.storage.list_prefix == nullptr) {
        return std::unexpected(invalid_transport_error());
    }
    if (!valid_list_prefix(prefix)) {
        return std::unexpected(make_error(ErrorCode::InvalidIdentifier,
                                          "prefixo de listagem inválido"));
    }

    platform::perf_trace::count("transport list prefix");
    return transport.storage.list_prefix(state, prefix);
}

std::expected<std::string, Error> physical_hash(Transport& transport,
                                                std::string_view identifier,
                                                std::string_view algorithm) {
    auto* state = state_pointer(transport);
    if (state == nullptr || transport.storage.physical_hash == nullptr) {
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "transporte não oferece hash físico remoto"));
    }
    return transport.storage.physical_hash(state, identifier, algorithm);
}

PhysicalHashBatchResult
physical_hash_batch(Transport& transport,
                    const PhysicalHashBatchRequest& request) {
    if (!valid(transport)) {
        return std::unexpected(invalid_transport_error());
    }
    auto validation = validate_physical_hash_batch_request(request);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    if (transport.storage.physical_hash_batch == nullptr) {
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "transporte não oferece hash físico remoto em lote"));
    }
    return transport.storage.physical_hash_batch(transport.state.get(),
                                                 request);
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
    auto validation = validate_control_read_batch_request(request);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    if (transport.storage.control_read_batch == nullptr) {
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "transporte não oferece batch de leituras de controle"));
    }
    return transport.storage.control_read_batch(transport.state.get(), request);
}

RemovalResult remove(Transport& transport, std::string_view identifier) {
    auto* state = state_pointer(transport);
    if (state == nullptr || transport.storage.remove == nullptr) {
        return std::unexpected(invalid_transport_error());
    }

    auto removed = transport.storage.remove(state, identifier);
    if (removed || !mutation_result_is_ambiguous(removed.error())) {
        return removed;
    }

    auto observed = presence(transport, identifier);
    if (observed && *observed == Presence::Absent) {
        return Removal::Removed;
    }
    return std::unexpected(removed.error());
}

} // namespace kasumi::transport
