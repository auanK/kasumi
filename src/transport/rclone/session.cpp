#include "detail.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/random.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <future>
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#if !defined(_WIN32)
extern char** environ;
#endif

namespace kasumi::transport::rclone_detail {
namespace {

Error make_error(ErrorCode code, std::string message, int native_code = 0) {
    return Error{.code = code,
                 .message = std::move(message),
                 .native_code = native_code};
}

bool environment_name_equal(std::string_view left,
                            std::string_view right) noexcept {
    if (left.size() != right.size()) {
        return false;
    }
#if defined(_WIN32)
    return std::ranges::equal(left, right, [](char a, char b) {
        const auto fold = [](char value) {
            return value >= 'a' && value <= 'z'
                       ? static_cast<char>(value - ('a' - 'A'))
                       : value;
        };
        return fold(a) == fold(b);
    });
#else
    return left == right;
#endif
}

bool environment_name_starts_with(std::string_view name,
                                  std::string_view prefix) noexcept {
    return name.size() >= prefix.size() &&
           environment_name_equal(name.substr(0, prefix.size()), prefix);
}

bool excluded_environment_name(std::string_view name,
                               const ChildEnvironment& controlled) noexcept {
    return environment_name_starts_with(name, "KASUMI_") ||
           std::ranges::any_of(controlled, [&](const auto& entry) {
               return environment_name_equal(name, entry.first);
           });
}

std::optional<std::filesystem::path>
normalized_regular_executable(const std::filesystem::path& candidate) {
    std::error_code error;
    const auto canonical = std::filesystem::canonical(candidate, error);
    if (error) {
        return std::nullopt;
    }
    const auto status = std::filesystem::status(canonical, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        return std::nullopt;
    }
#if !defined(_WIN32)
    if (::access(canonical.c_str(), X_OK) != 0) {
        return std::nullopt;
    }
#endif
    return canonical;
}

bool path_is_within(const std::filesystem::path& candidate,
                    const std::filesystem::path& root) {
    if (root.empty()) {
        return false;
    }
    std::error_code error;
    const auto absolute_root = std::filesystem::absolute(root, error);
    if (error) {
        return false;
    }
    const auto canonical_root =
        std::filesystem::weakly_canonical(absolute_root, error);
    if (error) {
        return false;
    }
    auto candidate_component = candidate.begin();
    for (auto root_component = canonical_root.begin();
         root_component != canonical_root.end();
         ++root_component, ++candidate_component) {
        if (candidate_component == candidate.end()) {
            return false;
        }
#if defined(_WIN32)
        const auto left = candidate_component->wstring();
        const auto right = root_component->wstring();
        if (CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) !=
            CSTR_EQUAL) {
            return false;
        }
#else
        if (*candidate_component != *root_component) {
            return false;
        }
#endif
    }
    return true;
}

std::filesystem::path executable_name(std::filesystem::path value) {
#if defined(_WIN32)
    if (!value.has_extension()) {
        value += ".exe";
    }
#endif
    return value;
}

std::filesystem::path::string_type executable_search_path() {
#if defined(_WIN32)
    std::wstring result;
    auto required = GetEnvironmentVariableW(L"PATH", nullptr, 0);
    while (required != 0) {
        result.resize(required);
        const auto length =
            GetEnvironmentVariableW(L"PATH", result.data(), required);
        if (length < required) {
            result.resize(length);
            return result;
        }
        required = length;
    }
    return {};
#else
    const char* value = std::getenv("PATH");
    return value != nullptr ? value : "";
#endif
}

ChildEnvironment controlled_environment(const State& state) {
    ChildEnvironment result{
        {"RCLONE_RC_ADDR", "127.0.0.1:" + std::to_string(state.port)},
        {"RCLONE_RC_USER", state.username},
        {"RCLONE_RC_PASS", state.password},
        {"RCLONE_RC_BASEURL", state.base_url},
        {"RCLONE_RC_NO_AUTH", "false"},
        {"RCLONE_RC_SERVE", "false"},
        {"RCLONE_RC_WEB_GUI", "false"},
        {"RCLONE_RC_ENABLE_METRICS", "false"},
        {"RCLONE_RC_FILES", ""},
        {"RCLONE_RC_HTPASSWD", ""},
        {"RCLONE_RC_USER_FROM_HEADER", ""},
        {"RCLONE_RC_ALLOW_ORIGIN", ""},
        {"RCLONE_RC_CERT", ""},
        {"RCLONE_RC_KEY", ""},
        {"RCLONE_RC_CLIENT_CA", ""},
        {"RCLONE_RC_MAX_HEADER_BYTES", "4096"},
        {"RCLONE_LOG_LEVEL", "ERROR"},
        {"RCLONE_STATS", "0"},
    };
    if (state.configuration.config_path) {
        result.emplace_back(
            "RCLONE_CONFIG",
            platform::path::to_utf8(*state.configuration.config_path));
    }
    return result;
}

#if defined(_WIN32)

std::expected<std::string, Error> utf8(std::wstring_view text) {
    if (text.empty()) {
        return std::string{};
    }
    if (text.size() >
        static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        return std::unexpected(make_error(
            ErrorCode::ProcessFailure, "variável de ambiente grande demais"));
    }
    const auto size = WideCharToMultiByte(CP_UTF8,
                                          WC_ERR_INVALID_CHARS,
                                          text.data(),
                                          static_cast<int>(text.size()),
                                          nullptr,
                                          0,
                                          nullptr,
                                          nullptr);
    if (size <= 0) {
        return std::unexpected(
            make_error(ErrorCode::ProcessFailure,
                       "não foi possível codificar o ambiente do rclone",
                       static_cast<int>(GetLastError())));
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8,
                            WC_ERR_INVALID_CHARS,
                            text.data(),
                            static_cast<int>(text.size()),
                            result.data(),
                            size,
                            nullptr,
                            nullptr) != size) {
        return std::unexpected(
            make_error(ErrorCode::ProcessFailure,
                       "não foi possível codificar o ambiente do rclone",
                       static_cast<int>(GetLastError())));
    }
    return result;
}

#endif

std::expected<void, Error>
validate_configuration(const detail::RcloneConfiguration& configuration) {
    if (configuration.executable.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "o executável do rclone não pode ser vazio"));
    }
    if (configuration.config_path && configuration.config_path->empty()) {
        return std::unexpected(make_error(
            ErrorCode::InvalidContext,
            "o caminho de configuração do rclone não pode ser vazio"));
    }
    return {};
}

std::expected<std::uint16_t, Error> find_available_loopback_port() {
#if defined(_WIN32)
    WSADATA data{};
    const int startup = WSAStartup(MAKEWORD(2, 2), &data);
    if (startup != 0) {
        return std::unexpected(make_error(
            ErrorCode::ProcessFailure, "WSAStartup falhou", startup));
    }
    const SOCKET socket_handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET) {
        const int error = WSAGetLastError();
        WSACleanup();
        return std::unexpected(
            make_error(ErrorCode::ProcessFailure, "socket falhou", error));
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0);
    if (::bind(socket_handle,
               reinterpret_cast<const sockaddr*>(&address),
               sizeof(address)) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        closesocket(socket_handle);
        WSACleanup();
        return std::unexpected(make_error(
            ErrorCode::ProcessFailure, "bind de loopback falhou", error));
    }
    int address_length = sizeof(address);
    if (::getsockname(socket_handle,
                      reinterpret_cast<sockaddr*>(&address),
                      &address_length) == SOCKET_ERROR ||
        address.sin_port == 0) {
        const int error = WSAGetLastError();
        closesocket(socket_handle);
        WSACleanup();
        return std::unexpected(
            make_error(ErrorCode::ProcessFailure, "getsockname falhou", error));
    }
    const auto port = ntohs(address.sin_port);
    closesocket(socket_handle);
    WSACleanup();
    return port;
#else
    const int socket_handle = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket_handle < 0) {
        return std::unexpected(
            make_error(ErrorCode::ProcessFailure, "socket falhou", errno));
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0);
    if (::bind(socket_handle,
               reinterpret_cast<const sockaddr*>(&address),
               sizeof(address)) != 0) {
        const int error = errno;
        ::close(socket_handle);
        return std::unexpected(make_error(
            ErrorCode::ProcessFailure, "bind de loopback falhou", error));
    }
    socklen_t address_length = sizeof(address);
    if (::getsockname(socket_handle,
                      reinterpret_cast<sockaddr*>(&address),
                      &address_length) != 0 ||
        address.sin_port == 0) {
        const int error = errno;
        ::close(socket_handle);
        return std::unexpected(
            make_error(ErrorCode::ProcessFailure, "getsockname falhou", error));
    }
    const auto port = ntohs(address.sin_port);
    ::close(socket_handle);
    return port;
#endif
}

std::error_code drain_process_output(State& state) {
    std::uint8_t buffer[4096]{};
    for (;;) {
        if (state.stop_drain.load()) {
            return {};
        }
        int events = 0;
        std::error_code poll_error;
        std::error_code read_error;
        {
            std::lock_guard process_lock(state.process_mutex);
            std::tie(events, poll_error) = state.process.poll(
                reproc::event::out | reproc::event::err | reproc::event::exit,
                reproc::milliseconds(100));
            if (poll_error) {
                return poll_error;
            }
            if ((events & (reproc::event::out | reproc::event::err)) != 0) {
                const auto stream = (events & reproc::event::out) != 0
                                        ? reproc::stream::out
                                        : reproc::stream::err;
                std::tie(std::ignore, read_error) =
                    state.process.read(stream, buffer, sizeof(buffer));
            }
        }

        if (read_error && read_error != reproc::error::broken_pipe) {
            return read_error;
        }
        if ((events & reproc::event::exit) != 0 &&
            (events & (reproc::event::out | reproc::event::err)) == 0) {
            return {};
        }
    }
}

void wait_for_drain(State& state) noexcept {
    if (!state.drain_future.valid()) {
        return;
    }
    try {
        state.drain_future.get();
    } catch (...) {
    }
}

bool stop_process(State& state) noexcept {
    if (!state.process_started) {
        return true;
    }
    bool stopped = false;
    try {
        std::lock_guard process_lock(state.process_mutex);
        const auto result = state.process.stop(reproc::stop_actions{
            {reproc::stop::wait, reproc::milliseconds(2000)},
            {reproc::stop::terminate, reproc::milliseconds(2000)},
            {reproc::stop::kill, reproc::milliseconds(2000)},
        });
        stopped = !result.second && result.first >= 0;
    } catch (...) {
    }
    if (!stopped) {
        try {
            std::lock_guard process_lock(state.process_mutex);
            (void)state.process.kill();
        } catch (...) {
        }
        try {
            std::lock_guard process_lock(state.process_mutex);
            const auto waited = state.process.wait(reproc::milliseconds(2000));
            stopped = !waited.second && waited.first >= 0;
        } catch (...) {
            stopped = false;
        }
    }
    try {
        std::lock_guard process_lock(state.process_mutex);
        (void)state.process.close(reproc::stream::out);
        (void)state.process.close(reproc::stream::err);
    } catch (...) {
    }
    if (stopped) {
        state.process_started = false;
    }
    return stopped;
}

void clear_secrets(State& state) noexcept {
    std::fill(state.username.begin(), state.username.end(), '\0');
    std::fill(state.password.begin(), state.password.end(), '\0');
    state.username.clear();
    state.password.clear();
}

bool reset_failed_attempt(State& state) noexcept {
    const bool stopped = stop_process(state);
    wait_for_drain(state);
    state.port = 0;
    state.ready = false;
    clear_secrets(state);
    state.base_url.clear();
    return stopped;
}

std::expected<int, Error> start_process(State& state) {
    const auto trace = platform::perf_trace::begin();
    auto environment = make_child_environment(state);
    if (!environment) {
        return std::unexpected(environment.error());
    }
    reproc::options options;
    options.env.behavior = reproc::env::empty;
    options.env.extra = reproc::env{*environment};
    options.redirect.in.type = reproc::redirect::discard;
    options.redirect.out.type = reproc::redirect::pipe;
    options.redirect.err.type = reproc::redirect::pipe;
    const std::vector<std::string> arguments{
        platform::path::to_utf8(state.configuration.executable), "rcd"};
    const auto result = state.process.start(arguments, options);
    platform::perf_trace::finish("rclone process startup", trace);
    if (result) {
        return std::unexpected(make_error(
            ErrorCode::ProcessFailure,
            "não foi possível iniciar o processo rclone em " +
                platform::path::to_utf8(state.configuration.executable),
            result.value()));
    }
    state.process_started = true;
    const auto child_pid = state.process.pid();
    if (child_pid.second) {
        return std::unexpected(
            make_error(ErrorCode::ProcessFailure,
                       "não foi possível consultar o PID do rclone",
                       child_pid.second.value()));
    }
    try {
        state.drain_future = std::async(std::launch::async, [&state]() {
            return drain_process_output(state);
        });
    } catch (const std::exception& exception) {
        return std::unexpected(make_error(
            ErrorCode::ProcessFailure,
            std::string{"não foi possível drenar a saída do rclone: "} +
                exception.what()));
    }
    return child_pid.first;
}

std::expected<void, Error> prepare_attempt(State& state) {
    const auto port = find_available_loopback_port();
    if (!port) {
        return std::unexpected(port.error());
    }
    state.port = *port;
    const auto username = platform::random::hex_id(16);
    const auto password = platform::random::hex_id(32);
    const auto base_id = platform::random::hex_id(16);
    if (!username || !password || !base_id) {
        return std::unexpected(make_error(
            ErrorCode::ProcessFailure,
            "não foi possível gerar credenciais efêmeras para o RC"));
    }
    state.username = *username;
    state.password = *password;
    state.base_url = "/kasumi-" + *base_id;
    const auto started = start_process(state);
    if (!started) {
        return std::unexpected(started.error());
    }
    const auto readiness_trace = platform::perf_trace::begin();
    const auto connected = establish_rc_connection(state, *started);
    platform::perf_trace::finish("RC readiness", readiness_trace);
    if (!connected) {
        return std::unexpected(connected.error());
    }
    return {};
}

bool definitely_missing_executable(const Error& error) noexcept {
    return error.code == ErrorCode::ProcessFailure &&
           (error.native_code ==
                static_cast<int>(std::errc::no_such_file_or_directory) ||
            error.native_code ==
                static_cast<int>(std::errc::permission_denied));
}

} // namespace

std::expected<std::filesystem::path, Error>
resolve_rclone_executable(const detail::RcloneConfiguration& configuration) {
    if (configuration.executable.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "o executável do rclone não pode ser vazio"));
    }

    const auto accept =
        [&](const std::filesystem::path& candidate,
            bool found_through_path) -> std::optional<std::filesystem::path> {
        auto normalized = normalized_regular_executable(candidate);
        if (!normalized ||
            path_is_within(*normalized,
                           configuration.forbidden_executable_root)) {
            return std::nullopt;
        }
        if (found_through_path) {
            std::error_code error;
            const auto current = std::filesystem::current_path(error);
            if (!error && path_is_within(*normalized, current)) {
                return std::nullopt;
            }
        }
        return normalized;
    };

    const auto configured = executable_name(configuration.executable);
    if (configured.is_absolute() || configured.has_parent_path()) {
        std::error_code error;
        const auto candidate =
            configured.is_absolute()
                ? configured
                : std::filesystem::absolute(configured, error);
        if (!error) {
            if (auto accepted = accept(candidate, false)) {
                return *accepted;
            }
        }
        return std::unexpected(make_error(
            ErrorCode::ProcessFailure,
            "executável rclone inválido, fora da raiz permitida ou não "
            "regular: " +
                platform::path::to_utf8(configured),
            std::make_error_code(std::errc::permission_denied).value()));
    }

    const auto native_paths = executable_search_path();
    if (!native_paths.empty()) {
#if defined(_WIN32)
        constexpr wchar_t separator = L';';
#else
        constexpr char separator = ':';
#endif
        const std::basic_string_view paths{native_paths};
        std::size_t begin = 0;
        while (begin <= paths.size()) {
            const auto end = paths.find(separator, begin);
            auto entry = paths.substr(
                begin, end == paths.npos ? paths.size() - begin : end - begin);
            if (entry.size() >= 2 && entry.front() == '"' &&
                entry.back() == '"') {
                entry.remove_prefix(1);
                entry.remove_suffix(1);
            }
            const std::filesystem::path directory{entry};
            if (!directory.empty() && directory.is_absolute()) {
                if (auto accepted = accept(directory / configured, true)) {
                    return *accepted;
                }
            }
            if (end == paths.npos) {
                break;
            }
            begin = end + 1;
        }
    }

    return std::unexpected(make_error(
        ErrorCode::ProcessFailure,
        "rclone não encontrado em um diretório absoluto e permitido do PATH",
        std::make_error_code(std::errc::no_such_file_or_directory).value()));
}

std::expected<ChildEnvironment, Error>
make_child_environment(const State& state) {
    try {
        auto controlled = controlled_environment(state);
        ChildEnvironment result;
#if defined(_WIN32)
        using EnvironmentBlock =
            std::unique_ptr<wchar_t, decltype(&FreeEnvironmentStringsW)>;
        EnvironmentBlock block{GetEnvironmentStringsW(),
                               &FreeEnvironmentStringsW};
        if (!block) {
            return std::unexpected(
                make_error(ErrorCode::ProcessFailure,
                           "não foi possível ler o ambiente do processo",
                           static_cast<int>(GetLastError())));
        }
        for (const wchar_t* entry = block.get(); *entry != L'\0';
             entry += std::wcslen(entry) + 1) {
            const std::wstring_view text{entry};
            if (text.empty() || text.front() == L'=') {
                continue;
            }
            const auto separator = text.find(L'=');
            if (separator == std::wstring_view::npos || separator == 0) {
                continue;
            }
            auto name = utf8(text.substr(0, separator));
            auto value = utf8(text.substr(separator + 1));
            if (!name || !value) {
                return std::unexpected(!name ? name.error() : value.error());
            }
            if (!excluded_environment_name(*name, controlled)) {
                result.emplace_back(std::move(*name), std::move(*value));
            }
        }
#else
        for (char** entry = ::environ; entry != nullptr && *entry != nullptr;
             ++entry) {
            const std::string_view text{*entry};
            const auto separator = text.find('=');
            if (separator == std::string_view::npos || separator == 0) {
                continue;
            }
            const auto name = text.substr(0, separator);
            if (!excluded_environment_name(name, controlled)) {
                result.emplace_back(std::string{name},
                                    std::string{text.substr(separator + 1)});
            }
        }
#endif
        result.insert(result.end(),
                      std::make_move_iterator(controlled.begin()),
                      std::make_move_iterator(controlled.end()));
        return result;
    } catch (const std::bad_alloc&) {
        return std::unexpected(make_error(
            ErrorCode::Io, "não foi possível copiar o ambiente do rclone"));
    }
}

std::expected<State*, Error>
start_state(detail::RcloneConfiguration configuration) {
    if (const auto valid = validate_configuration(configuration); !valid) {
        return std::unexpected(valid.error());
    }
    auto executable = resolve_rclone_executable(configuration);
    if (!executable) {
        return std::unexpected(executable.error());
    }
    configuration.executable = std::move(*executable);
    std::unique_ptr<State> state;
    try {
        state = std::make_unique<State>();
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            make_error(ErrorCode::Io, "não foi possível alocar a sessão RC"));
    }
    state->configuration = std::move(configuration);
    Error last_error = make_error(ErrorCode::Unknown, "startup RC falhou");
    for (int attempt = 0; attempt < 3; ++attempt) {
        const auto result = prepare_attempt(*state);
        if (result) {
            return state.release();
        }
        last_error = result.error();
        const bool missing_executable =
            definitely_missing_executable(last_error);
        const bool cancelled = last_error.code == ErrorCode::Cancelled;
        const bool cleaned = reset_failed_attempt(*state);
        if (!cleaned || missing_executable || cancelled) {
            if (!cleaned) {
                last_error =
                    make_error(ErrorCode::ProcessFailure,
                               "não foi possível encerrar com segurança a "
                               "tentativa anterior do rclone");
            }
            break;
        }
    }
    last_error.message +=
        " (executável rclone: " +
        platform::path::to_utf8(state->configuration.executable) + ")";
    destroy_state(state.release());
    return std::unexpected(std::move(last_error));
}

void destroy_state(void* context) noexcept {
    auto* state = static_cast<State*>(context);
    if (state == nullptr) {
        return;
    }
    const auto trace = platform::perf_trace::begin();
    const auto drain_trace = platform::perf_trace::begin();
    state->stop_drain.store(true);
    wait_for_drain(*state);
    platform::perf_trace::finish("rclone output drain", drain_trace);
    const auto stop_trace = platform::perf_trace::begin();
    if (request_core_quit_best_effort(*state)) {
        const auto kill_trace = platform::perf_trace::begin();
        try {
            std::lock_guard process_lock(state->process_mutex);
            (void)state->process.kill();
        } catch (...) {
        }
        platform::perf_trace::finish("rclone acknowledged quit kill",
                                     kill_trace);
    }
    (void)stop_process(*state);
    platform::perf_trace::finish("rclone process stop", stop_trace);
    clear_secrets(*state);
    state->base_url.clear();
    delete state;
    platform::perf_trace::finish("rclone shutdown", trace);
}

} // namespace kasumi::transport::rclone_detail
