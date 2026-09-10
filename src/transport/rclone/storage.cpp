#include "detail.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
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
constexpr auto control_read_deadline = std::chrono::minutes{2};
constexpr auto transfer_timeout = std::chrono::minutes{30};

Error make_error(ErrorCode code, std::string message, int native_code = 0) {
    return Error{.code = code,
                 .message = std::move(message),
                 .native_code = native_code};
}

Error invalid_context_error() {
    return make_error(ErrorCode::InvalidContext, "sessão RC não está pronta");
}

Error invalid_identifier_error() {
    return make_error(ErrorCode::InvalidIdentifier,
                      "identificador de objeto inválido");
}

Error filesystem_error(const std::error_code& error) {
    return make_error(ErrorCode::Io, error.message(), error.value());
}

bool valid_identifier(std::string_view identifier) {
    if (identifier.empty() || identifier.find('\\') != std::string_view::npos) {
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
    return !normalized.empty() && normalized != "." &&
           !normalized.is_absolute() && !normalized.has_root_name() &&
           !normalized.has_root_directory();
}

bool valid_sha256(std::string_view value) noexcept {
    return value.size() == 64 && std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f') ||
                      (character >= 'A' && character <= 'F');
           });
}

bool valid_batch_identifier(std::string_view identifier) noexcept {
    return valid_identifier(identifier) &&
           identifier.find_first_of("/\\\r\n") == std::string_view::npos;
}

State* ready_state(void* context) noexcept {
    auto* state = static_cast<State*>(context);
    if (state == nullptr || !state->ready ||
        state->configuration.remote_name.empty()) {
        return nullptr;
    }
    return state;
}

std::string remote_fs(const State& state) {
    return state.configuration.remote_name + ":";
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

std::string objects_remote(const State& state) {
    return state.configuration.remote_root;
}

std::string objects_remote_fs(const State& state) {
    return remote_fs(state) + objects_remote(state);
}

std::string object_remote(const State& state, std::string_view identifier) {
    return join_remote_path(objects_remote(state), identifier);
}

std::expected<nlohmann::json, Error>
request_json_impl(State& state,
                  std::string_view endpoint,
                  const nlohmann::json& request,
                  std::size_t response_limit,
                  std::chrono::milliseconds read_timeout,
                  bool retry_transient_reads) {
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
            std::string{"resposta "} + std::string{endpoint} + " inválida"));
    }
}

std::expected<nlohmann::json, Error>
request_json(State& state,
             std::string_view endpoint,
             const nlohmann::json& request,
             std::size_t response_limit,
             std::chrono::milliseconds read_timeout) {
    return request_json_impl(
        state, endpoint, request, response_limit, read_timeout, false);
}

std::expected<nlohmann::json, Error>
request_read_json(State& state,
                  std::string_view endpoint,
                  const nlohmann::json& request,
                  std::size_t response_limit,
                  std::chrono::milliseconds deadline) {
    return request_json_impl(
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
            "resposta operations/check sem lista " + std::string{name}));
    }

    std::vector<std::string> entries;
    for (const auto& item : response.at(name)) {
        if (!item.is_string()) {
            return std::unexpected(make_error(
                ErrorCode::ProtocolFailure,
                "resposta operations/check contém entrada inválida"));
        }
        auto identifier = item.get<std::string>();
        if (!expected.contains(identifier) || !seen.insert(identifier).second) {
            return std::unexpected(make_error(
                ErrorCode::ProtocolFailure,
                "resposta operations/check contém identificador inesperado"));
        }
        entries.push_back(std::move(identifier));
    }
    return entries;
}

bool unsupported_check_endpoint(const Error& error) noexcept {
    return error.code == ErrorCode::ProtocolFailure &&
           error.native_code == 404 &&
           (error.message.find("operations/check") != std::string::npos ||
            error.message.find("method not found") != std::string::npos);
}

bool unsupported_job_batch_endpoint(const Error& error) noexcept {
    return error.code == ErrorCode::ProtocolFailure &&
           error.native_code == 404 &&
           (error.message.find("job/batch") != std::string::npos ||
            error.message.find("method not found") != std::string::npos);
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
        return std::unexpected(make_error(ErrorCode::InvalidContext,
                                          "caminho local sem diretório pai"));
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
                                              "arquivo de origem não existe"));
        }
        return std::unexpected(filesystem_error(error));
    }
    if (!regular) {
        return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                          "arquivo de origem não existe"));
    }
    return {};
}

std::expected<nlohmann::json, Error>
stat_remote(State& state, std::string_view remote, bool files_only = true) {
    return request_read_json(state,
                             "operations/stat",
                             nlohmann::json{
                                 {"fs", remote_fs(state)},
                                 {"remote", remote},
                                 {"opt",
                                  {{"filesOnly", files_only},
                                   {"noModTime", true},
                                   {"noMimeType", true}}},
                             },
                             maximum_response_size,
                             control_read_deadline);
}

bool not_found(const Error& error) noexcept {
    if (error.code == ErrorCode::ProtocolFailure) {
        if (error.native_code == 404) {
            return true;
        }
        if (error.message.find("directory not found") != std::string::npos ||
            error.message.find("not found") != std::string::npos) {
            return true;
        }
    }
    return false;
}

PresenceResult rclone_presence(void* context, std::string_view identifier);

Result rclone_initialize(void* context) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }

    const auto created =
        request_json(*state,
                     "operations/mkdir",
                     nlohmann::json{{"fs", remote_fs(*state)},
                                    {"remote", objects_remote(*state)}},
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
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }
    if (!valid_identifier(identifier)) {
        return std::unexpected(invalid_identifier_error());
    }

    const auto absolute_source = absolute_path(source);
    if (!absolute_source) {
        return std::unexpected(absolute_source.error());
    }
    const auto source_file = require_regular_source(*absolute_source);
    if (!source_file) {
        return source_file;
    }

    const auto source_name =
        platform::path::to_utf8(absolute_source->filename());
    const auto source_parent =
        platform::path::to_utf8(absolute_source->parent_path());
    if (source_name.empty() || source_parent.empty()) {
        return std::unexpected(make_error(ErrorCode::InvalidContext,
                                          "arquivo de origem inválido"));
    }

    const auto copy_trace = platform::perf_trace::begin();
    const auto copied =
        request_json(*state,
                     "operations/copyfile",
                     nlohmann::json{
                         {"srcFs", source_parent},
                         {"srcRemote", source_name},
                         {"dstFs", remote_fs(*state)},
                         {"dstRemote", object_remote(*state, identifier)},
                     },
                     maximum_response_size,
                     transfer_timeout);
    platform::perf_trace::finish("rclone copyfile upload", copy_trace);
    if (!copied) {
        return std::unexpected(copied.error());
    }
    return {};
}

Result rclone_put_batch(void* context, const PutBatch& batch) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }

    if (batch.identifiers.empty()) {
        return {};
    }

    const auto absolute_source = absolute_path(batch.source_root);
    if (!absolute_source) {
        return std::unexpected(absolute_source.error());
    }
    const auto source_path = platform::path::to_utf8(*absolute_source);

    nlohmann::json payload = {{"srcFs", source_path},
                              {"dstFs", objects_remote_fs(*state)},
                              {"createEmptySrcDirs", false}};
    nlohmann::json config = {{"NoTraverse", true}};
    if (batch.max_parallel_transfers > 0) {
        config["Transfers"] = batch.max_parallel_transfers;
    }
    payload["_config"] = std::move(config);

    const auto copied = request_json(
        *state, "sync/copy", payload, maximum_response_size, transfer_timeout);

    if (!copied) {
        return std::unexpected(copied.error());
    }
    return {};
}

Result rclone_get(void* context,
                  std::string_view identifier,
                  const std::filesystem::path& destination) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }
    if (!valid_identifier(identifier)) {
        return std::unexpected(invalid_identifier_error());
    }

    const auto absolute_destination = absolute_path(destination);
    if (!absolute_destination) {
        return std::unexpected(absolute_destination.error());
    }
    const auto parent = ensure_parent_directory(*absolute_destination);
    if (!parent) {
        return parent;
    }

    const auto destination_name =
        platform::path::to_utf8(absolute_destination->filename());
    const auto destination_parent =
        platform::path::to_utf8(absolute_destination->parent_path());
    if (destination_name.empty() || destination_parent.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext, "destino local inválido"));
    }

    const auto copy_trace = platform::perf_trace::begin();
    const auto copied =
        request_json(*state,
                     "operations/copyfile",
                     nlohmann::json{
                         {"srcFs", remote_fs(*state)},
                         {"srcRemote", object_remote(*state, identifier)},
                         {"dstFs", destination_parent},
                         {"dstRemote", destination_name},
                     },
                     maximum_response_size,
                     transfer_timeout);
    platform::perf_trace::finish("rclone copyfile download", copy_trace);
    if (!copied) {
        if (not_found(copied.error())) {
            return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                              "objeto remoto não existe"));
        }
        return std::unexpected(copied.error());
    }

    std::error_code error;
    if (!std::filesystem::is_regular_file(*absolute_destination, error)) {
        if (error) {
            return std::unexpected(filesystem_error(error));
        }
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "destino local não virou arquivo regular"));
    }
    return {};
}

Result rclone_get_batch(void* context, const GetBatch& batch) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
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

    nlohmann::json include_rules = nlohmann::json::array();
    for (const auto& identifier : batch.identifiers) {
        if (!valid_identifier(identifier)) {
            return std::unexpected(invalid_identifier_error());
        }
        include_rules.push_back("/" + identifier);
    }

    nlohmann::json payload = {
        {"srcFs",
         batch.source_prefix.empty()
             ? objects_remote_fs(*state)
             : join_remote_path(objects_remote_fs(*state),
                                batch.source_prefix)},
        {"dstFs", platform::path::to_utf8(*absolute_destination)},
        {"createEmptySrcDirs", false},
        {"_filter", {{"IncludeRule", std::move(include_rules)}}},
    };
    if (batch.max_parallel_transfers > 0) {
        payload["_config"] = {
            {"Transfers", batch.max_parallel_transfers},
        };
    }

    const auto copy_trace = platform::perf_trace::begin();
    const auto copied = request_read_json(
        *state, "sync/copy", payload, maximum_response_size, transfer_timeout);
    platform::perf_trace::finish("rclone batch download", copy_trace);
    if (!copied) {
        return std::unexpected(copied.error());
    }
    return {};
}

ListingResult parse_list_response_json(const nlohmann::json& response,
                                       std::string_view remote_prefix = {}) {
    if (!response.is_object() || !response.contains("list") ||
        !response["list"].is_array()) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "resposta operations/list inválida"));
    }

    std::vector<std::string> identifiers;
    std::unordered_set<std::string> seen;
    for (const auto& item : response["list"]) {
        if (!item.is_object() || !item.contains("Path") ||
            !item["Path"].is_string()) {
            return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                              "item operations/list inválido"));
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
                           "operations/list retornou um Path inválido"));
        }
        if (!seen.insert(identifier).second) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "o remote retornou identificadores duplicados"));
        }
        identifiers.push_back(std::move(identifier));
    }
    std::ranges::sort(identifiers);
    return identifiers;
}

PresenceResult rclone_presence(void* context, std::string_view identifier) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }
    if (!valid_identifier(identifier)) {
        return std::unexpected(invalid_identifier_error());
    }

    const auto presence_trace = platform::perf_trace::begin();
    const auto response =
        stat_remote(*state, object_remote(*state, identifier));
    platform::perf_trace::finish("rc/presence", presence_trace);
    if (!response) {
        if (not_found(response.error())) {
            return Presence::Absent;
        }
        return std::unexpected(response.error());
    }
    if (!response->is_object() || !response->contains("item")) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "resposta operations/stat inválida"));
    }
    const auto& item = (*response)["item"];
    if (item.is_null()) {
        return Presence::Absent;
    }
    if (!item.is_object()) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "resposta operations/stat inválida"));
    }
    if (item.contains("IsDir")) {
        if (!item["IsDir"].is_boolean()) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "resposta operations/stat inválida"));
        }
        if (item["IsDir"].get<bool>()) {
            return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                              "objeto remoto é um diretório"));
        }
    }
    return Presence::Present;
}

ListingResult rclone_list(void* context) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }

    const auto list_trace = platform::perf_trace::begin();
    const auto response =
        request_read_json(*state,
                          "operations/list",
                          nlohmann::json{
                              {"fs", remote_fs(*state)},
                              {"remote", objects_remote(*state)},
                              {"opt",
                               {{"recurse", true},
                                {"filesOnly", true},
                                {"noModTime", true},
                                {"noMimeType", true}}},
                          },
                          maximum_list_response_size,
                          control_read_deadline);
    platform::perf_trace::finish("rc/list", list_trace);
    if (!response) {
        if (not_found(response.error())) {
            return std::unexpected(
                make_error(ErrorCode::StorageNotFound,
                           "diretório remoto de objetos não existe"));
        }
        return std::unexpected(response.error());
    }
    return parse_list_response_json(*response, objects_remote(*state));
}

ListingResult rclone_list_prefix(void* context, std::string_view prefix) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }
    if (!valid_identifier(prefix)) {
        return std::unexpected(invalid_identifier_error());
    }

    const auto remote = join_remote_path(objects_remote(*state), prefix);
    const auto list_trace = platform::perf_trace::begin();
    const auto response = request_read_json(*state,
                                            "operations/list",
                                            nlohmann::json{
                                                {"fs", remote_fs(*state)},
                                                {"remote", remote},
                                                {"opt",
                                                 {{"recurse", false},
                                                  {"filesOnly", true},
                                                  {"noModTime", true},
                                                  {"noMimeType", true}}},
                                            },
                                            maximum_list_response_size,
                                            control_read_deadline);
    platform::perf_trace::finish("rc/list_prefix", list_trace);
    if (!response) {
        if (not_found(response.error())) {
            return std::unexpected(
                make_error(ErrorCode::StorageNotFound,
                           "diretório remoto de objetos não existe"));
        }
        return std::unexpected(response.error());
    }
    auto result = parse_list_response_json(*response, remote);
    if (!result) {
        return result;
    }
    const auto relative_prefix = std::string{prefix} + "/";
    for (auto& name : *result) {
        if (name.starts_with(relative_prefix)) {
            name.erase(0, relative_prefix.size());
        }
    }
    return result;
}

std::expected<std::string, Error> rclone_physical_hash(
    void* context, std::string_view identifier, std::string_view algorithm) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }
    if (!valid_identifier(identifier)) {
        return std::unexpected(invalid_identifier_error());
    }
    if (algorithm != "sha256" ||
        state->sha256_unsupported.load(std::memory_order_relaxed)) {
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "rclone backend does not expose algorithm"));
    }

    const auto response = request_read_json(
        *state,
        "operations/hashsumfile",
        nlohmann::json{{"fs", remote_fs(*state)},
                       {"remote", object_remote(*state, identifier)},
                       {"hashType", "SHA-256"}},
        maximum_response_size,
        control_read_deadline);
    if (!response) {
        if (not_found(response.error())) {
            return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                              "objeto remoto não existe"));
        }
        if (response.error().code == ErrorCode::Unsupported ||
            response.error().native_code == 400 ||
            response.error().native_code == 501) {
            state->sha256_unsupported.store(true, std::memory_order_relaxed);
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
        state->sha256_unsupported.store(true, std::memory_order_relaxed);
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "rclone returned an ambiguous physical hash response"));
    }
    const auto returned_algorithm = response->at("hashType").get<std::string>();
    if (returned_algorithm != "sha256" && returned_algorithm != "SHA-256") {
        state->sha256_unsupported.store(true, std::memory_order_relaxed);
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "rclone returned a different physical hash algorithm"));
    }
    auto digest = response->at("hash").get<std::string>();
    if (!valid_sha256(digest)) {
        state->sha256_unsupported.store(true, std::memory_order_relaxed);
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "rclone returned an ambiguous physical hash"));
    }
    std::ranges::transform(digest, digest.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return digest;
}

PhysicalHashBatchResult
rclone_physical_hash_batch(void* context,
                           const PhysicalHashBatchRequest& request) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }
    auto algorithm = request.algorithm;
    std::ranges::transform(
        algorithm, algorithm.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    if (algorithm != "sha256" ||
        state->sha256_unsupported.load(std::memory_order_relaxed)) {
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "rclone backend does not expose algorithm em lote"));
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
                           "hash esperado não é SHA-256 válido"));
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
                       "scratch_root não é um diretório local real"));
    }

    std::ranges::sort(expectations, {}, &PhysicalHashExpectation::identifier);
    const auto manifest = *root / ".kasumi-batch-verify.sha256";
    const auto manifest_status =
        std::filesystem::symlink_status(manifest, status_error);
    if (status_error && status_error != std::errc::no_such_file_or_directory) {
        return std::unexpected(filesystem_error(status_error));
    }
    if (!status_error && std::filesystem::exists(manifest_status)) {
        return std::unexpected(make_error(
            ErrorCode::InvalidContext, "manifesto de verificação já existe"));
    }

    {
        std::ofstream output(manifest, std::ios::binary);
        if (!output) {
            return std::unexpected(make_error(
                ErrorCode::Io,
                "não foi possível criar o manifesto de verificação"));
        }
        for (const auto& object : expectations) {
            output << object.expected_hash << "  " << object.identifier << '\n';
        }
        if (!output.good()) {
            std::error_code ignored;
            std::filesystem::remove(manifest, ignored);
            return std::unexpected(make_error(
                ErrorCode::Io,
                "não foi possível gravar o manifesto de verificação"));
        }
    }

    const auto manifest_parent = platform::path::to_utf8(*root);
    const auto response = request_read_json(
        *state,
        "operations/check",
        nlohmann::json{
            {"dstFs", objects_remote_fs(*state)},
            {"checkFileHash", "SHA-256"},
            {"checkFileFs", manifest_parent},
            {"checkFileRemote", platform::path::to_utf8(manifest.filename())},
            {"oneWay", true},
            {"missingOnSrc", false},
            {"missingOnDst", true},
            {"match", true},
            {"differ", true},
            {"error", true},
        },
        maximum_check_response_size,
        transfer_timeout);
    std::error_code manifest_error;
    const bool manifest_removed =
        std::filesystem::remove(manifest, manifest_error);
    if (manifest_error || !manifest_removed) {
        return std::unexpected(
            make_error(ErrorCode::Io,
                       "não foi possível remover o manifesto de verificação"));
    }
    if (!response) {
        if (unsupported_check_endpoint(response.error()) ||
            response.error().code == ErrorCode::Unsupported ||
            response.error().native_code == 400 ||
            response.error().native_code == 501) {
            state->sha256_unsupported.store(true, std::memory_order_relaxed);
            return std::unexpected(
                make_error(ErrorCode::Unsupported,
                           "rclone não oferece operations/check",
                           response.error().native_code));
        }
        return std::unexpected(response.error());
    }

    auto report = parse_physical_hash_batch_response(response->dump(), request);
    if (!report) {
        return std::unexpected(report.error());
    }

    platform::perf_trace::count("content batch verify objects",
                                request.objects.size());
    return report;
}

ControlReadBatchResponse
rclone_control_read_batch(void* context,
                          const ControlReadBatchRequest& request) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }

    nlohmann::json inputs = nlohmann::json::array();
    for (const auto& prefix : request.list_prefixes) {
        inputs.push_back(nlohmann::json{
            {"_path", "operations/list"},
            {"fs", remote_fs(*state)},
            {"remote", join_remote_path(objects_remote(*state), prefix)},
            {"opt",
             {{"recurse", false},
              {"filesOnly", true},
              {"noModTime", true},
              {"noMimeType", true}}}});
    }
    for (const auto& identifier : request.presence_identifiers) {
        inputs.push_back(
            nlohmann::json{{"_path", "operations/stat"},
                           {"fs", remote_fs(*state)},
                           {"remote", object_remote(*state, identifier)},
                           {"opt",
                            {{"filesOnly", true},
                             {"noModTime", true},
                             {"noMimeType", true}}}});
    }

    const auto response = request_read_json(
        *state,
        "job/batch",
        // Admission depends on the ordering LIST writers -> STAT barrier;
        // rclone executes inputs sequentially when concurrency <= 1.
        nlohmann::json{{"inputs", std::move(inputs)}, {"concurrency", 1}},
        maximum_list_response_size,
        control_read_deadline);
    if (!response) {
        if (unsupported_job_batch_endpoint(response.error())) {
            return std::unexpected(make_error(ErrorCode::Unsupported,
                                              "rclone não oferece job/batch",
                                              response.error().native_code));
        }
        return std::unexpected(response.error());
    }
    auto result = parse_control_read_batch_response(
        response->dump(), request, objects_remote(*state));
    if (!result) {
        return result;
    }

    platform::perf_trace::count("control batch operations",
                                request.list_prefixes.size() +
                                    request.presence_identifiers.size());
    return result;
}

RemovalResult rclone_remove(void* context, std::string_view identifier) {
    auto* state = ready_state(context);
    if (state == nullptr) {
        return std::unexpected(invalid_context_error());
    }
    if (!valid_identifier(identifier)) {
        return std::unexpected(invalid_identifier_error());
    }

    const auto deleted = request_json(
        *state,
        "operations/deletefile",
        nlohmann::json{{"fs", remote_fs(*state)},
                       {"remote", object_remote(*state, identifier)}},
        maximum_response_size,
        quick_timeout);
    if (!deleted) {
        if (not_found(deleted.error())) {
            return Removal::AlreadyAbsent;
        }
        return std::unexpected(deleted.error());
    }
    return Removal::Removed;
}

} // namespace

ControlReadBatchResponse
parse_control_read_batch_response(std::string_view response_body,
                                  const ControlReadBatchRequest& request,
                                  std::string_view objects_root) {
    try {
        const auto response = nlohmann::json::parse(response_body);
        const auto expected_size =
            request.list_prefixes.size() + request.presence_identifiers.size();
        if (!response.is_object() || !response.contains("results") ||
            !response.at("results").is_array() ||
            response.at("results").size() != expected_size) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "resposta job/batch de controle inválida"));
        }

        const auto missing =
            [](const nlohmann::json& item) -> std::expected<bool, Error> {
            if (!item.is_object()) {
                return std::unexpected(
                    make_error(ErrorCode::ProtocolFailure,
                               "resultado job/batch inválido"));
            }
            std::optional<int> status;
            if (item.contains("status")) {
                if (!item.at("status").is_number_integer()) {
                    return std::unexpected(
                        make_error(ErrorCode::ProtocolFailure,
                                   "status job/batch inválido"));
                }
                status = item.at("status").get<int>();
            }
            if (item.contains("error")) {
                if (!item.at("error").is_string() ||
                    item.at("error").get<std::string>().empty() || !status) {
                    return std::unexpected(
                        make_error(ErrorCode::ProtocolFailure,
                                   "erro de subcomando job/batch inválido"));
                }
                if (*status == 404) {
                    return true;
                }
                return std::unexpected(make_error(
                    ErrorCode::ProtocolFailure,
                    "subcomando job/batch falhou; detalhe remoto omitido"));
            }
            if (status && (*status < 200 || *status >= 300)) {
                return std::unexpected(
                    make_error(ErrorCode::ProtocolFailure,
                               "status de subcomando job/batch indica falha"));
            }
            return false;
        };

        ControlReadBatchResult result;
        result.listings.reserve(request.list_prefixes.size());
        result.presences.reserve(request.presence_identifiers.size());
        for (std::size_t index = 0; index < request.list_prefixes.size();
             ++index) {
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
                                   "resultado 404 job/batch contraditório"));
                }
                result.listings.emplace_back();
                continue;
            }
            auto listing = parse_list_response_json(
                item,
                join_remote_path(objects_root, request.list_prefixes[index]));
            if (!listing) {
                return std::unexpected(listing.error());
            }
            result.listings.push_back(std::move(*listing));
        }

        for (std::size_t offset = 0;
             offset < request.presence_identifiers.size();
             ++offset) {
            const auto& item = response.at("results").at(
                request.list_prefixes.size() + offset);
            auto absent = missing(item);
            if (!absent) {
                return std::unexpected(absent.error());
            }
            if (*absent) {
                if (item.contains("item") && !item.at("item").is_null()) {
                    return std::unexpected(
                        make_error(ErrorCode::ProtocolFailure,
                                   "resultado 404 job/batch contraditório"));
                }
                result.presences.push_back(Presence::Absent);
                continue;
            }
            if (!item.contains("item")) {
                return std::unexpected(make_error(
                    ErrorCode::ProtocolFailure,
                    "resposta operations/stat inválida no job/batch"));
            }
            const auto& remote_item = item.at("item");
            if (remote_item.is_null()) {
                result.presences.push_back(Presence::Absent);
                continue;
            }
            if (!remote_item.is_object() ||
                (remote_item.contains("IsDir") &&
                 !remote_item.at("IsDir").is_boolean())) {
                return std::unexpected(make_error(
                    ErrorCode::ProtocolFailure,
                    "resposta operations/stat inválida no job/batch"));
            }
            if (remote_item.value("IsDir", false)) {
                return std::unexpected(
                    make_error(ErrorCode::ProtocolFailure,
                               "objeto de controle remoto é um diretório"));
            }
            result.presences.push_back(Presence::Present);
        }
        return result;
    } catch (const std::exception&) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "resposta job/batch de controle inválida"));
    }
}

PhysicalHashBatchResult
parse_physical_hash_batch_response(std::string_view response_body,
                                   const PhysicalHashBatchRequest& request) {
    try {
        const auto response = nlohmann::json::parse(response_body);
        if (!response.is_object() || !response.contains("success") ||
            !response.at("success").is_boolean() ||
            !response.contains("hashType") ||
            !response.at("hashType").is_string()) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "resposta operations/check inválida"));
        }

        auto hash_type = response.at("hashType").get<std::string>();
        std::ranges::transform(
            hash_type, hash_type.begin(), [](unsigned char character) {
                return static_cast<char>(std::tolower(character));
            });
        if (hash_type != "sha256") {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "operations/check retornou algoritmo inesperado"));
        }

        std::unordered_set<std::string> expected;
        for (const auto& object : request.objects) {
            if (!expected.insert(object.identifier).second) {
                return std::unexpected(make_error(
                    ErrorCode::InvalidIdentifier,
                    "identificadores duplicados na requisição de hash físico"));
            }
        }

        std::unordered_set<std::string> seen;
        auto matched = check_entries(response, "match", expected, seen);
        auto mismatched = check_entries(response, "differ", expected, seen);
        auto missing = check_entries(response, "missingOnDst", expected, seen);
        auto errors = check_entries(response, "error", expected, seen);
        if (!matched || !mismatched || !missing || !errors) {
            const auto& failure =
                !matched ? matched
                         : (!mismatched ? mismatched
                                        : (!missing ? missing : errors));
            return std::unexpected(failure.error());
        }

        const bool success = response.at("success").get<bool>();
        const bool has_failures =
            !mismatched->empty() || !missing->empty() || !errors->empty();
        if (seen.size() != expected.size() ||
            (success && (has_failures || matched->size() != expected.size())) ||
            (!success && !has_failures)) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "resposta operations/check inconsistente"));
        }

        return PhysicalHashBatchReport{
            .mismatched = std::move(*mismatched),
            .missing = std::move(*missing),
            .errors = std::move(*errors),
        };
    } catch (const std::exception&) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure, "resposta operations/check inválida"));
    }
}

ListingResult parse_list_response(std::string_view response_body) {
    try {
        return parse_list_response_json(nlohmann::json::parse(response_body));
    } catch (const std::exception&) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "resposta operations/list inválida"));
    }
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
        .physical_hash_batch_min_objects = 6,
    };
}

} // namespace kasumi::transport::rclone_detail
