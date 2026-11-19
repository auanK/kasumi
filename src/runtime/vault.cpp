#include "runtime/vault.hpp"

#include "platform/durability.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <monocypher.h>
#include <string>
#include <string_view>
#include <system_error>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>
#include <wincred.h>
// clang-format on
#elif defined(__linux__)
#include <cctype>
#include <cstdlib>
#include <dlfcn.h>
#include <mutex>
#include <optional>
#include <unistd.h>
#include <vector>
#endif

namespace kasumi::runtime::vault {

namespace {

template <typename T> struct WipeGuard {
    T& value;
    bool* skip = nullptr;
    ~WipeGuard() noexcept {
        if (skip == nullptr || !*skip) {
            crypto_wipe(value.data(), value.size());
        }
    }
};

} // namespace

constexpr std::string_view MAGIC = "KASUMI_EDGE_SYNC_V1_MASK";

std::expected<KeyBytes, runtime::Error> decode_hex(std::string_view text) {
    if (text.size() != KEY_SIZE * 2) {
        return fail(ErrorCode::KeyInvalid,
                    "KASUMI_MASTER_KEY must be 64 hexadecimal characters");
    }
    const auto digit = [](char value) -> int {
        if (value >= '0' && value <= '9')
            return value - '0';
        if (value >= 'a' && value <= 'f')
            return value - 'a' + 10;
        if (value >= 'A' && value <= 'F')
            return value - 'A' + 10;
        return -1;
    };
    KeyBytes key{};
    WipeGuard guard{key};
    for (std::size_t index = 0; index < key.size(); ++index) {
        const int high = digit(text[index * 2]);
        const int low = digit(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return fail(ErrorCode::KeyInvalid,
                        "KASUMI_MASTER_KEY contains non-hexadecimal character");
        }
        key[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return key;
}

void obscure(std::span<std::uint8_t, KEY_SIZE> key) {
    for (std::size_t i = 0; i < KEY_SIZE; ++i) {
        key[i] ^= static_cast<uint8_t>(MAGIC[i % MAGIC.size()]);
    }
}

std::expected<KeyBytes, runtime::Error>
read_impl(const std::filesystem::path& path, bool protect) {
    if (protect) {
        if (auto secured = platform::private_storage::protect_file(path);
            !secured) {
            return fail(ErrorCode::KeyNotFound, secured.error());
        }
    } else {
        std::error_code filesystem_error;
        const auto status =
            std::filesystem::symlink_status(path, filesystem_error);
        if (filesystem_error ||
            status.type() == std::filesystem::file_type::not_found ||
            std::filesystem::is_symlink(status) ||
            !std::filesystem::is_regular_file(status)) {
            return fail(ErrorCode::KeyNotFound,
                        "key.bin file is missing or invalid; run 'kasumi key "
                        "<profile>' to re-enter the key");
        }
    }
    KeyBytes key{};
    WipeGuard key_guard{key};
    std::array<std::uint8_t, KEY_SIZE + 1> buf{};
    WipeGuard buf_guard{buf};
    std::size_t total = 0;

    auto streamed = platform::private_storage::stream_regular_file(
        path, buf, [&](std::span<const std::uint8_t> chunk) -> bool {
            const std::size_t copy = std::min(chunk.size(), key.size() - total);
            if (copy > 0) {
                std::memcpy(key.data() + total, chunk.data(), copy);
            }
            total += chunk.size();
            return total <= key.size();
        });
    if (!streamed) {
        if (streamed.error().kind ==
            platform::private_storage::StreamErrorKind::Aborted) {
            return fail(ErrorCode::KeyInvalid, "key.bin file has invalid size");
        }
        return fail(ErrorCode::KeyNotFound,
                    "key.bin file is missing or corrupted; run 'kasumi key "
                    "<profile>' to re-enter the key");
    }
    if (total != key.size()) {
        return fail(ErrorCode::KeyNotFound,
                    "key.bin file is missing or corrupted; run 'kasumi key "
                    "<profile>' to re-enter the key");
    }
    obscure(key);
    return key;
}

std::expected<KeyBytes, runtime::Error>
read(const std::filesystem::path& path) {
    return read_impl(path, true);
}

std::expected<KeyBytes, runtime::Error>
read_only(const std::filesystem::path& path) {
    return read_impl(path, false);
}

namespace {

std::expected<KeyBytes, Error>
prepare_write_key(const std::filesystem::path& path,
                  const KeyBytes& clear_key) {
    if (auto parent =
            platform::private_storage::ensure_directory(path.parent_path());
        !parent) {
        return fail(ErrorCode::IoFailure, parent.error());
    }
    KeyBytes stored = clear_key;
    obscure(stored);
    return stored;
}

} // namespace

std::expected<void, runtime::Error> write(const std::filesystem::path& path,
                                          const KeyBytes& clear_key) {
    auto stored = prepare_write_key(path, clear_key);
    if (!stored) {
        return std::unexpected(stored.error());
    }
    WipeGuard guard{*stored};
    const std::string_view bytes{reinterpret_cast<const char*>(stored->data()),
                                 stored->size()};
    if (auto saved = platform::private_storage::write_atomically(path, bytes);
        !saved) {
        return fail(ErrorCode::KeyWriteFailure, saved.error());
    }
    return {};
}

std::expected<void, runtime::Error>
write_new(const std::filesystem::path& path,
          const KeyBytes& clear_key,
          platform::private_storage::FileIdentity& identity) {
    identity = {};
    auto stored = prepare_write_key(path, clear_key);
    if (!stored) {
        return std::unexpected(stored.error());
    }
    WipeGuard guard{*stored};
    auto file = platform::private_storage::create_private_file(path);
    if (!file) {
        return fail(ErrorCode::KeyWriteFailure, file.error().message);
    }
    identity = file->identity;
    if (auto written = platform::private_storage::write_private_file(
            *file, stored->data(), stored->size());
        !written) {
        return fail(ErrorCode::KeyWriteFailure, written.error());
    }
    if (auto flushed =
            platform::private_storage::flush_and_close_private_file(*file);
        !flushed) {
        return fail(ErrorCode::KeyWriteFailure, flushed.error());
    }
    if (auto synced = platform::durability::sync_parent_directory(path);
        !synced) {
        return fail(ErrorCode::KeyWriteFailure, synced.error());
    }
    return {};
}

namespace {

#if defined(_WIN32)
template <typename Operation> DWORD credential_call(Operation operation) {
    for (unsigned attempt = 0;; ++attempt) {
        if (operation()) {
            return ERROR_SUCCESS;
        }
        const auto error = GetLastError();
        if (attempt == 3 ||
            (error != ERROR_SHARING_VIOLATION &&
             error != ERROR_LOCK_VIOLATION && error != ERROR_BUSY &&
             error != ERROR_ACCESS_DENIED)) {
            return error;
        }
        Sleep(10UL << attempt);
    }
}

std::string credential_error(std::string_view operation, DWORD error) {
    return "Windows Credential Manager: " + std::string{operation} + " (" +
           std::to_string(error) + "): " +
           std::error_code{static_cast<int>(error), std::system_category()}
               .message();
}

std::wstring vault_target_name(const std::filesystem::path& key_path) {
    std::error_code ec;
    const auto abs = std::filesystem::absolute(key_path, ec);
    const auto normalized = (ec ? key_path : abs).lexically_normal();
    std::wstring target = L"kasumi:" + normalized.generic_wstring();
    for (auto& ch : target) {
        if (ch >= L'A' && ch <= L'Z') {
            ch = static_cast<wchar_t>(ch - L'A' + L'a');
        }
    }
    return target;
}
#elif defined(__linux__)
template <typename Fn>
bool load_symbol(void* handle, const char* name, Fn& out) noexcept {
    void* symbol = dlsym(handle, name);
    if (symbol == nullptr) {
        return false;
    }
    static_assert(sizeof(out) == sizeof(symbol));
    std::memcpy(&out, &symbol, sizeof(out));
    return true;
}

void wipe_string(std::string& value) noexcept {
    if (!value.empty()) {
        crypto_wipe(value.data(), value.size());
        value.clear();
    }
}

struct StringWiper {
    std::string& value;
    ~StringWiper() noexcept {
        wipe_string(value);
    }
};

std::string linux_vault_target_name(const std::filesystem::path& key_path) {
    std::error_code ec;
    const auto abs = std::filesystem::absolute(key_path, ec);
    const auto normalized = (ec ? key_path : abs).lexically_normal();
    return "kasumi:" + normalized.generic_string();
}

std::string encode_obscured_hex(const KeyBytes& clear_key) {
    constexpr char digits[] = "0123456789abcdef";
    KeyBytes stored = clear_key;
    obscure(stored);
    WipeGuard guard{stored};
    std::string hex(KEY_SIZE * 2, '\0');
    for (std::size_t i = 0; i < KEY_SIZE; ++i) {
        hex[i * 2] = digits[stored[i] >> 4];
        hex[i * 2 + 1] = digits[stored[i] & 0x0fU];
    }
    return hex;
}

std::expected<KeyBytes, runtime::Error>
decode_obscured_hex(std::string_view hex) {
    auto decoded = decode_hex(hex);
    if (!decoded) {
        return fail(ErrorCode::KeyInvalid, "OS vault key has invalid format");
    }
    WipeGuard guard{*decoded};
    obscure(*decoded);
    return *decoded;
}

bool has_session_dbus() noexcept {
    if (const char* env = std::getenv("DBUS_SESSION_BUS_ADDRESS")) {
        return *env != '\0';
    }
    if (const char* xdg = std::getenv("XDG_RUNTIME_DIR")) {
        if (*xdg == '\0') {
            return false;
        }
        const std::string runtime_bus = std::string{xdg} + "/bus";
        return ::access(runtime_bus.c_str(), R_OK | W_OK) == 0;
    }
    return false;
}

bool contains_ci(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty() || haystack.size() < needle.size()) {
        return false;
    }
    for (std::size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            const auto a = static_cast<unsigned char>(haystack[i + j]);
            const auto b = static_cast<unsigned char>(needle[j]);
            if (std::tolower(a) != std::tolower(b)) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

bool desktop_prefers_kde() noexcept {
    for (const char* var : {"XDG_CURRENT_DESKTOP", "DESKTOP_SESSION"}) {
        if (const char* val = std::getenv(var)) {
            if (contains_ci(val, "kde") || contains_ci(val, "plasma")) {
                return true;
            }
        }
    }
    return false;
}

struct SecretApi {
    struct GError {
        std::uint32_t domain;
        int code;
        char* message;
    };
    struct SecretSchemaAttribute {
        const char* name;
        int type;
    };
    struct SecretSchema {
        const char* name;
        int flags;
        SecretSchemaAttribute attributes[32];
        int reserved;
        void* reserved1;
        void* reserved2;
        void* reserved3;
        void* reserved4;
        void* reserved5;
        void* reserved6;
        void* reserved7;
    };

    using StoreSyncFn = int (*)(const SecretSchema*,
                                const char*,
                                const char*,
                                const char*,
                                void*,
                                GError**,
                                ...);
    using LookupSyncFn = char* (*)(const SecretSchema*, void*, GError**, ...);
    using ClearSyncFn = int (*)(const SecretSchema*, void*, GError**, ...);
    using PasswordFreeFn = void (*)(char*);
    using ErrorFreeFn = void (*)(GError*);

    StoreSyncFn store_sync = nullptr;
    LookupSyncFn lookup_sync = nullptr;
    ClearSyncFn clear_sync = nullptr;
    PasswordFreeFn password_free = nullptr;
    ErrorFreeFn error_free = nullptr;
    bool loaded = false;

    static const SecretApi& instance() noexcept {
        static SecretApi api = []() {
            SecretApi res;
            void* handle = dlopen("libsecret-1.so.0", RTLD_LAZY | RTLD_LOCAL);
            if (handle == nullptr) {
                return res;
            }
            bool ok =
                load_symbol(
                    handle, "secret_password_store_sync", res.store_sync) &&
                load_symbol(
                    handle, "secret_password_lookup_sync", res.lookup_sync) &&
                load_symbol(
                    handle, "secret_password_clear_sync", res.clear_sync) &&
                load_symbol(handle, "secret_password_free", res.password_free);
            if (!load_symbol(handle, "g_error_free", res.error_free)) {
                void* glib = dlopen("libglib-2.0.so.0", RTLD_LAZY | RTLD_LOCAL);
                if (glib == nullptr ||
                    !load_symbol(glib, "g_error_free", res.error_free)) {
                    ok = false;
                }
            }
            res.loaded = ok;
            return res;
        }();
        return api;
    }

    static const SecretSchema* schema() noexcept {
        static const SecretSchema kSchema{"io.github.kasumi.VaultKey",
                                          0,
                                          {{"target", 0}, {nullptr, 0}},
                                          0,
                                          nullptr,
                                          nullptr,
                                          nullptr,
                                          nullptr,
                                          nullptr,
                                          nullptr,
                                          nullptr};
        return &kSchema;
    }
};

struct DbusApi {
    using dbus_bool_t = std::uint32_t;
    using dbus_int32_t = std::int32_t;
    using dbus_int64_t = std::int64_t;
    struct DbusConnection;
    struct DbusMessage;
    struct DbusError {
        const char* name;
        const char* message;
        unsigned int dummy1 : 1;
        unsigned int dummy2 : 1;
        unsigned int dummy3 : 1;
        unsigned int dummy4 : 1;
        unsigned int dummy5 : 1;
        void* padding1;
    };

    static constexpr int kBusSession = 0;
    static constexpr int kTypeInvalid = '\0';
    static constexpr int kTypeBoolean = 'b';
    static constexpr int kTypeInt32 = 'i';
    static constexpr int kTypeInt64 = 'x';
    static constexpr int kTypeString = 's';
    static constexpr int kTypeArray = 'a';
    static constexpr int kMessageTypeError = 3;

    using ThreadsInitFn = dbus_bool_t (*)();
    using ErrorInitFn = void (*)(DbusError*);
    using ErrorFreeFn = void (*)(DbusError*);
    using ErrorIsSetFn = dbus_bool_t (*)(const DbusError*);
    using BusGetFn = DbusConnection* (*)(int, DbusError*);
    using ConnUnrefFn = void (*)(DbusConnection*);
    using ConnSetExitOnDisconnectFn = void (*)(DbusConnection*, dbus_bool_t);
    using MsgNewMethodCallFn = DbusMessage* (*)(const char*,
                                                const char*,
                                                const char*,
                                                const char*);
    using MsgUnrefFn = void (*)(DbusMessage*);
    using MsgGetTypeFn = int (*)(DbusMessage*);
    using MsgGetErrorNameFn = const char* (*)(DbusMessage*);
    using MsgAppendArgsFn = dbus_bool_t (*)(DbusMessage*, int, ...);
    using MsgGetArgsFn = dbus_bool_t (*)(DbusMessage*, DbusError*, int, ...);
    using ConnSendReplyFn = DbusMessage* (*)(DbusConnection*,
                                             DbusMessage*,
                                             int,
                                             DbusError*);
    using FreeStringArrayFn = void (*)(char**);

    ThreadsInitFn threads_init_default = nullptr;
    ErrorInitFn error_init = nullptr;
    ErrorFreeFn error_free = nullptr;
    ErrorIsSetFn error_is_set = nullptr;
    BusGetFn bus_get = nullptr;
    ConnUnrefFn conn_unref = nullptr;
    ConnSetExitOnDisconnectFn conn_set_exit_on_disconnect = nullptr;
    MsgNewMethodCallFn msg_new_method_call = nullptr;
    MsgUnrefFn msg_unref = nullptr;
    MsgGetTypeFn msg_get_type = nullptr;
    MsgGetErrorNameFn msg_get_error_name = nullptr;
    MsgAppendArgsFn msg_append_args = nullptr;
    MsgGetArgsFn msg_get_args = nullptr;
    ConnSendReplyFn conn_send_with_reply_and_block = nullptr;
    FreeStringArrayFn free_string_array = nullptr;
    bool loaded = false;

    static const DbusApi& instance() noexcept {
        static DbusApi api = []() {
            DbusApi res;
            void* handle = dlopen("libdbus-1.so.3", RTLD_LAZY | RTLD_LOCAL);
            if (handle == nullptr) {
                return res;
            }
            const bool ok =
                load_symbol(handle,
                            "dbus_threads_init_default",
                            res.threads_init_default) &&
                load_symbol(handle, "dbus_error_init", res.error_init) &&
                load_symbol(handle, "dbus_error_free", res.error_free) &&
                load_symbol(handle, "dbus_error_is_set", res.error_is_set) &&
                load_symbol(handle, "dbus_bus_get", res.bus_get) &&
                load_symbol(handle, "dbus_connection_unref", res.conn_unref) &&
                load_symbol(handle,
                            "dbus_connection_set_exit_on_disconnect",
                            res.conn_set_exit_on_disconnect) &&
                load_symbol(handle,
                            "dbus_message_new_method_call",
                            res.msg_new_method_call) &&
                load_symbol(handle, "dbus_message_unref", res.msg_unref) &&
                load_symbol(
                    handle, "dbus_message_get_type", res.msg_get_type) &&
                load_symbol(handle,
                            "dbus_message_get_error_name",
                            res.msg_get_error_name) &&
                load_symbol(
                    handle, "dbus_message_append_args", res.msg_append_args) &&
                load_symbol(
                    handle, "dbus_message_get_args", res.msg_get_args) &&
                load_symbol(handle,
                            "dbus_connection_send_with_reply_and_block",
                            res.conn_send_with_reply_and_block) &&
                load_symbol(
                    handle, "dbus_free_string_array", res.free_string_array);
            if (ok) {
                res.threads_init_default();
                res.loaded = true;
            }
            return res;
        }();
        return api;
    }
};

struct DbusErrorGuard {
    const DbusApi& dbus;
    DbusApi::DbusError err{};
    explicit DbusErrorGuard(const DbusApi& api) noexcept : dbus(api) {
        dbus.error_init(&err);
    }
    ~DbusErrorGuard() noexcept {
        dbus.error_free(&err);
    }
    std::string message(std::string_view fallback) const {
        return err.message != nullptr ? std::string{err.message}
                                      : std::string{fallback};
    }
};

struct DbusMsgGuard {
    const DbusApi& dbus;
    DbusApi::DbusMessage* msg = nullptr;
    ~DbusMsgGuard() noexcept {
        if (msg != nullptr) {
            dbus.msg_unref(msg);
        }
    }
};

struct DbusConnGuard {
    const DbusApi& dbus;
    DbusApi::DbusConnection* conn = nullptr;
    ~DbusConnGuard() noexcept {
        if (conn != nullptr) {
            dbus.conn_unref(conn);
        }
    }
};

std::expected<DbusApi::DbusConnection*, runtime::Error>
connect_session_dbus(const DbusApi& dbus, ErrorCode err_code) {
    if (!dbus.loaded) {
        return fail(err_code, "libdbus-1.so.3 is not available on this system");
    }
    DbusErrorGuard err{dbus};
    DbusApi::DbusConnection* conn =
        dbus.bus_get(DbusApi::kBusSession, &err.err);
    if (conn == nullptr || dbus.error_is_set(&err.err) != 0) {
        return fail(err_code,
                    err.message("failed to connect to D-Bus session bus"));
    }
    dbus.conn_set_exit_on_disconnect(conn, 0);
    return conn;
}

template <typename AppendFn>
std::expected<DbusApi::DbusMessage*, std::string>
dbus_call(const DbusApi& dbus,
          DbusApi::DbusConnection* conn,
          const char* service,
          const char* path,
          const char* iface,
          const char* method,
          AppendFn&& append_fn,
          int timeout_ms = 25000) {
    DbusMsgGuard msg{dbus,
                     dbus.msg_new_method_call(service, path, iface, method)};
    if (msg.msg == nullptr) {
        return std::unexpected("failed to allocate D-Bus method call");
    }
    if (!append_fn(msg.msg)) {
        return std::unexpected("failed to serialize D-Bus arguments");
    }
    DbusErrorGuard err{dbus};
    DbusApi::DbusMessage* reply = dbus.conn_send_with_reply_and_block(
        conn, msg.msg, timeout_ms, &err.err);
    if (reply == nullptr || dbus.error_is_set(&err.err) != 0) {
        if (reply != nullptr) {
            dbus.msg_unref(reply);
        }
        return std::unexpected(
            err.message(std::string{"D-Bus call failed: "} + method));
    }
    if (dbus.msg_get_type(reply) == DbusApi::kMessageTypeError) {
        const char* ename = dbus.msg_get_error_name(reply);
        std::string detail = ename != nullptr ? ename : "D-Bus error reply";
        dbus.msg_unref(reply);
        return std::unexpected(std::move(detail));
    }
    return reply;
}

bool dbus_name_has_owner(const DbusApi& dbus,
                         DbusApi::DbusConnection* conn,
                         const char* name) {
    auto reply = dbus_call(
        dbus,
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "NameHasOwner",
        [&](DbusApi::DbusMessage* m) {
            return dbus.msg_append_args(
                       m, DbusApi::kTypeString, &name, DbusApi::kTypeInvalid) !=
                   0;
        },
        2000);
    if (!reply) {
        return false;
    }
    DbusMsgGuard guard{dbus, *reply};
    DbusErrorGuard err{dbus};
    DbusApi::dbus_bool_t owned = 0;
    if (dbus.msg_get_args(*reply,
                          &err.err,
                          DbusApi::kTypeBoolean,
                          &owned,
                          DbusApi::kTypeInvalid) == 0) {
        return false;
    }
    return owned != 0;
}

bool dbus_name_activatable(const DbusApi& dbus,
                           DbusApi::DbusConnection* conn,
                           std::string_view name) {
    auto reply = dbus_call(
        dbus,
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "ListActivatableNames",
        [](DbusApi::DbusMessage*) {
            return true;
        },
        2000);
    if (!reply) {
        return false;
    }
    DbusMsgGuard guard{dbus, *reply};
    DbusErrorGuard err{dbus};
    char** names = nullptr;
    int count = 0;
    if (dbus.msg_get_args(*reply,
                          &err.err,
                          DbusApi::kTypeArray,
                          DbusApi::kTypeString,
                          &names,
                          &count,
                          DbusApi::kTypeInvalid) == 0 ||
        names == nullptr) {
        return false;
    }
    bool found = false;
    for (int i = 0; i < count; ++i) {
        if (names[i] != nullptr && name == names[i]) {
            found = true;
            break;
        }
    }
    dbus.free_string_array(names);
    return found;
}

struct KWalletEndpoint {
    const char* service;
    const char* path;
};

constexpr std::array<KWalletEndpoint, 3> kKWalletEndpoints{{
    {"org.kde.ksecretd", "/ksecretd"},
    {"org.kde.kwalletd6", "/modules/kwalletd6"},
    {"org.kde.kwalletd5", "/modules/kwalletd5"},
}};

constexpr const char* kKWalletInterface = "org.kde.KWallet";
constexpr const char* kKWalletFolder = "kasumi";
constexpr const char* kKWalletAppId = "kasumi";

std::expected<DbusApi::dbus_int32_t, runtime::Error>
open_kwallet_handle(const DbusApi& dbus,
                    DbusApi::DbusConnection* conn,
                    const KWalletEndpoint& ep,
                    ErrorCode err_code) {
    auto enabled_reply = dbus_call(dbus,
                                   conn,
                                   ep.service,
                                   ep.path,
                                   kKWalletInterface,
                                   "isEnabled",
                                   [](DbusApi::DbusMessage*) {
                                       return true;
                                   });
    if (!enabled_reply) {
        return fail(err_code, enabled_reply.error());
    }
    {
        DbusMsgGuard g{dbus, *enabled_reply};
        DbusErrorGuard err{dbus};
        DbusApi::dbus_bool_t enabled = 0;
        if (dbus.msg_get_args(*enabled_reply,
                              &err.err,
                              DbusApi::kTypeBoolean,
                              &enabled,
                              DbusApi::kTypeInvalid) == 0 ||
            enabled == 0) {
            return fail(err_code, "KDE Wallet is disabled");
        }
    }

    std::string wallet_name = "kdewallet";
    if (auto lw_reply = dbus_call(dbus,
                                  conn,
                                  ep.service,
                                  ep.path,
                                  kKWalletInterface,
                                  "localWallet",
                                  [](DbusApi::DbusMessage*) {
                                      return true;
                                  })) {
        DbusMsgGuard g{dbus, *lw_reply};
        DbusErrorGuard err{dbus};
        const char* lw = nullptr;
        if (dbus.msg_get_args(*lw_reply,
                              &err.err,
                              DbusApi::kTypeString,
                              &lw,
                              DbusApi::kTypeInvalid) != 0 &&
            lw != nullptr && *lw != '\0') {
            wallet_name = lw;
        }
    }

    auto open_reply =
        dbus_call(dbus,
                  conn,
                  ep.service,
                  ep.path,
                  kKWalletInterface,
                  "open",
                  [&](DbusApi::DbusMessage* m) {
                      const char* w = wallet_name.c_str();
                      DbusApi::dbus_int64_t wid = 0;
                      const char* app = kKWalletAppId;
                      return dbus.msg_append_args(m,
                                                  DbusApi::kTypeString,
                                                  &w,
                                                  DbusApi::kTypeInt64,
                                                  &wid,
                                                  DbusApi::kTypeString,
                                                  &app,
                                                  DbusApi::kTypeInvalid) != 0;
                  });
    if (!open_reply) {
        return fail(err_code, open_reply.error());
    }
    DbusMsgGuard g{dbus, *open_reply};
    DbusErrorGuard err{dbus};
    DbusApi::dbus_int32_t handle = -1;
    if (dbus.msg_get_args(*open_reply,
                          &err.err,
                          DbusApi::kTypeInt32,
                          &handle,
                          DbusApi::kTypeInvalid) == 0 ||
        handle < 0) {
        return fail(err_code, "failed to open KDE Wallet");
    }
    return handle;
}

struct KWalletSession {
    KWalletEndpoint endpoint;
    DbusApi::dbus_int32_t handle = -1;
};

// Returns std::nullopt when no KDE Wallet service exists or is activatable.
std::expected<std::optional<KWalletSession>, runtime::Error>
open_kwallet_session(const DbusApi& dbus,
                     DbusApi::DbusConnection* conn,
                     ErrorCode err_code) {
    std::vector<KWalletEndpoint> candidates;
    std::array<bool, kKWalletEndpoints.size()> queued{};
    for (std::size_t i = 0; i < kKWalletEndpoints.size(); ++i) {
        if (dbus_name_has_owner(dbus, conn, kKWalletEndpoints[i].service)) {
            candidates.push_back(kKWalletEndpoints[i]);
            queued[i] = true;
        }
    }
    for (std::size_t i = 0; i < kKWalletEndpoints.size(); ++i) {
        if (!queued[i] &&
            dbus_name_activatable(dbus, conn, kKWalletEndpoints[i].service)) {
            candidates.push_back(kKWalletEndpoints[i]);
            queued[i] = true;
        }
    }
    if (candidates.empty()) {
        return std::nullopt;
    }

    std::optional<runtime::Error> last_error;
    for (const auto& ep : candidates) {
        auto handle = open_kwallet_handle(dbus, conn, ep, err_code);
        if (handle) {
            return KWalletSession{.endpoint = ep, .handle = *handle};
        }
        last_error = handle.error();
    }

    // Activating kwalletd6 on KF6 starts ksecretd dynamically without a
    // .service file for org.kde.ksecretd; retry ksecretd directly if it is now
    // owned.
    if (!queued[0] &&
        dbus_name_has_owner(dbus, conn, kKWalletEndpoints[0].service)) {
        auto handle =
            open_kwallet_handle(dbus, conn, kKWalletEndpoints[0], err_code);
        if (handle) {
            return KWalletSession{.endpoint = kKWalletEndpoints[0],
                                  .handle = *handle};
        }
        last_error = handle.error();
    }
    return std::unexpected(std::move(*last_error));
}

std::expected<bool, runtime::Error>
kwallet_check_bool(const DbusApi& dbus,
                   DbusApi::DbusConnection* conn,
                   const KWalletEndpoint& ep,
                   const char* method,
                   DbusApi::dbus_int32_t handle,
                   const char* item_name,
                   bool with_folder,
                   ErrorCode err_code) {
    auto reply = dbus_call(
        dbus,
        conn,
        ep.service,
        ep.path,
        kKWalletInterface,
        method,
        [&](DbusApi::DbusMessage* m) {
            const char* folder = kKWalletFolder;
            const char* app = kKWalletAppId;
            if (with_folder) {
                return dbus.msg_append_args(m,
                                            DbusApi::kTypeInt32,
                                            &handle,
                                            DbusApi::kTypeString,
                                            &folder,
                                            DbusApi::kTypeString,
                                            &item_name,
                                            DbusApi::kTypeString,
                                            &app,
                                            DbusApi::kTypeInvalid) != 0;
            }
            return dbus.msg_append_args(m,
                                        DbusApi::kTypeInt32,
                                        &handle,
                                        DbusApi::kTypeString,
                                        &item_name,
                                        DbusApi::kTypeString,
                                        &app,
                                        DbusApi::kTypeInvalid) != 0;
        });
    if (!reply) {
        return fail(err_code, reply.error());
    }
    DbusMsgGuard g{dbus, *reply};
    DbusErrorGuard err{dbus};
    DbusApi::dbus_bool_t flag = 0;
    if (dbus.msg_get_args(*reply,
                          &err.err,
                          DbusApi::kTypeBoolean,
                          &flag,
                          DbusApi::kTypeInvalid) == 0) {
        return fail(err_code,
                    std::string{"invalid D-Bus response from "} + method);
    }
    return flag != 0;
}

std::expected<KeyBytes, runtime::Error>
kwallet_read(const std::string& target) {
    const auto& dbus = DbusApi::instance();
    auto conn_res = connect_session_dbus(dbus, ErrorCode::KeyNotFound);
    if (!conn_res) {
        return std::unexpected(conn_res.error());
    }
    DbusConnGuard conn{dbus, *conn_res};
    auto session_res =
        open_kwallet_session(dbus, conn.conn, ErrorCode::KeyNotFound);
    if (!session_res) {
        return std::unexpected(session_res.error());
    }
    if (!*session_res) {
        return fail(ErrorCode::KeyNotFound,
                    "KDE Wallet service is not available");
    }
    const auto& session = **session_res;
    auto has_folder = kwallet_check_bool(dbus,
                                         conn.conn,
                                         session.endpoint,
                                         "hasFolder",
                                         session.handle,
                                         kKWalletFolder,
                                         false,
                                         ErrorCode::KeyNotFound);
    if (!has_folder) {
        return std::unexpected(has_folder.error());
    }
    if (!*has_folder) {
        return fail(ErrorCode::KeyNotFound,
                    "profile key is missing in OS vault; run 'kasumi key "
                    "<profile>' to re-enter the key");
    }
    auto has_entry = kwallet_check_bool(dbus,
                                        conn.conn,
                                        session.endpoint,
                                        "hasEntry",
                                        session.handle,
                                        target.c_str(),
                                        true,
                                        ErrorCode::KeyNotFound);
    if (!has_entry) {
        return std::unexpected(has_entry.error());
    }
    if (!*has_entry) {
        return fail(ErrorCode::KeyNotFound,
                    "profile key is missing in OS vault; run 'kasumi key "
                    "<profile>' to re-enter the key");
    }
    auto reply =
        dbus_call(dbus,
                  conn.conn,
                  session.endpoint.service,
                  session.endpoint.path,
                  kKWalletInterface,
                  "readPassword",
                  [&](DbusApi::DbusMessage* m) {
                      const char* folder = kKWalletFolder;
                      const char* key = target.c_str();
                      const char* app = kKWalletAppId;
                      return dbus.msg_append_args(m,
                                                  DbusApi::kTypeInt32,
                                                  &session.handle,
                                                  DbusApi::kTypeString,
                                                  &folder,
                                                  DbusApi::kTypeString,
                                                  &key,
                                                  DbusApi::kTypeString,
                                                  &app,
                                                  DbusApi::kTypeInvalid) != 0;
                  });
    if (!reply) {
        return fail(ErrorCode::KeyNotFound, reply.error());
    }
    DbusMsgGuard g{dbus, *reply};
    DbusErrorGuard err{dbus};
    const char* value = nullptr;
    if (dbus.msg_get_args(*reply,
                          &err.err,
                          DbusApi::kTypeString,
                          &value,
                          DbusApi::kTypeInvalid) == 0 ||
        value == nullptr) {
        return fail(ErrorCode::KeyInvalid,
                    "failed to read password from KDE Wallet");
    }
    std::string hex{value};
    StringWiper wiper{hex};
    return decode_obscured_hex(hex);
}

std::expected<void, runtime::Error> kwallet_write(const std::string& target,
                                                  const KeyBytes& clear_key) {
    const auto& dbus = DbusApi::instance();
    auto conn_res = connect_session_dbus(dbus, ErrorCode::KeyWriteFailure);
    if (!conn_res) {
        return std::unexpected(conn_res.error());
    }
    DbusConnGuard conn{dbus, *conn_res};
    auto session_res =
        open_kwallet_session(dbus, conn.conn, ErrorCode::KeyWriteFailure);
    if (!session_res) {
        return std::unexpected(session_res.error());
    }
    if (!*session_res) {
        return fail(ErrorCode::KeyWriteFailure,
                    "KDE Wallet service is not available");
    }
    const auto& session = **session_res;
    auto has_folder = kwallet_check_bool(dbus,
                                         conn.conn,
                                         session.endpoint,
                                         "hasFolder",
                                         session.handle,
                                         kKWalletFolder,
                                         false,
                                         ErrorCode::KeyWriteFailure);
    if (!has_folder) {
        return std::unexpected(has_folder.error());
    }
    if (!*has_folder) {
        auto created = kwallet_check_bool(dbus,
                                          conn.conn,
                                          session.endpoint,
                                          "createFolder",
                                          session.handle,
                                          kKWalletFolder,
                                          false,
                                          ErrorCode::KeyWriteFailure);
        if (!created || !*created) {
            return fail(ErrorCode::KeyWriteFailure,
                        created ? "failed to create KDE Wallet folder"
                                : created.error().detail);
        }
    }
    std::string hex = encode_obscured_hex(clear_key);
    StringWiper wiper{hex};
    auto reply =
        dbus_call(dbus,
                  conn.conn,
                  session.endpoint.service,
                  session.endpoint.path,
                  kKWalletInterface,
                  "writePassword",
                  [&](DbusApi::DbusMessage* m) {
                      const char* folder = kKWalletFolder;
                      const char* key = target.c_str();
                      const char* val = hex.c_str();
                      const char* app = kKWalletAppId;
                      return dbus.msg_append_args(m,
                                                  DbusApi::kTypeInt32,
                                                  &session.handle,
                                                  DbusApi::kTypeString,
                                                  &folder,
                                                  DbusApi::kTypeString,
                                                  &key,
                                                  DbusApi::kTypeString,
                                                  &val,
                                                  DbusApi::kTypeString,
                                                  &app,
                                                  DbusApi::kTypeInvalid) != 0;
                  });
    if (!reply) {
        return fail(ErrorCode::KeyWriteFailure, reply.error());
    }
    DbusMsgGuard g{dbus, *reply};
    DbusErrorGuard err{dbus};
    DbusApi::dbus_int32_t rc = -1;
    if (dbus.msg_get_args(*reply,
                          &err.err,
                          DbusApi::kTypeInt32,
                          &rc,
                          DbusApi::kTypeInvalid) == 0 ||
        rc != 0) {
        return fail(ErrorCode::KeyWriteFailure,
                    "failed to store key in KDE Wallet");
    }
    return {};
}

std::expected<void, runtime::Error> kwallet_delete(const std::string& target) {
    const auto& dbus = DbusApi::instance();
    auto conn_res = connect_session_dbus(dbus, ErrorCode::IoFailure);
    if (!conn_res) {
        return std::unexpected(conn_res.error());
    }
    DbusConnGuard conn{dbus, *conn_res};
    auto session_res =
        open_kwallet_session(dbus, conn.conn, ErrorCode::IoFailure);
    if (!session_res) {
        return std::unexpected(session_res.error());
    }
    if (!*session_res) {
        return {};
    }
    const auto& session = **session_res;
    auto has_folder = kwallet_check_bool(dbus,
                                         conn.conn,
                                         session.endpoint,
                                         "hasFolder",
                                         session.handle,
                                         kKWalletFolder,
                                         false,
                                         ErrorCode::IoFailure);
    if (!has_folder || !*has_folder) {
        return has_folder ? std::expected<void, runtime::Error>{}
                          : std::unexpected(has_folder.error());
    }
    auto has_entry = kwallet_check_bool(dbus,
                                        conn.conn,
                                        session.endpoint,
                                        "hasEntry",
                                        session.handle,
                                        target.c_str(),
                                        true,
                                        ErrorCode::IoFailure);
    if (!has_entry || !*has_entry) {
        return has_entry ? std::expected<void, runtime::Error>{}
                         : std::unexpected(has_entry.error());
    }
    auto reply =
        dbus_call(dbus,
                  conn.conn,
                  session.endpoint.service,
                  session.endpoint.path,
                  kKWalletInterface,
                  "removeEntry",
                  [&](DbusApi::DbusMessage* m) {
                      const char* folder = kKWalletFolder;
                      const char* key = target.c_str();
                      const char* app = kKWalletAppId;
                      return dbus.msg_append_args(m,
                                                  DbusApi::kTypeInt32,
                                                  &session.handle,
                                                  DbusApi::kTypeString,
                                                  &folder,
                                                  DbusApi::kTypeString,
                                                  &key,
                                                  DbusApi::kTypeString,
                                                  &app,
                                                  DbusApi::kTypeInvalid) != 0;
                  });
    if (!reply) {
        return fail(ErrorCode::IoFailure, reply.error());
    }
    DbusMsgGuard g{dbus, *reply};
    DbusErrorGuard err{dbus};
    DbusApi::dbus_int32_t rc = -1;
    if (dbus.msg_get_args(*reply,
                          &err.err,
                          DbusApi::kTypeInt32,
                          &rc,
                          DbusApi::kTypeInvalid) == 0 ||
        rc != 0) {
        return fail(ErrorCode::IoFailure,
                    "failed to delete key from KDE Wallet");
    }
    return {};
}

std::expected<KeyBytes, runtime::Error>
secret_service_read(const std::string& target) {
    const auto& secret = SecretApi::instance();
    if (!secret.loaded) {
        return fail(ErrorCode::KeyNotFound,
                    "libsecret-1.so.0 is not available on this system");
    }
    SecretApi::GError* err = nullptr;
    char* raw = secret.lookup_sync(SecretApi::schema(),
                                   nullptr,
                                   &err,
                                   "target",
                                   target.c_str(),
                                   static_cast<const char*>(nullptr));
    if (err != nullptr) {
        std::string msg =
            err->message != nullptr ? err->message : "Secret Service error";
        secret.error_free(err);
        if (raw != nullptr) {
            crypto_wipe(raw, std::strlen(raw));
            secret.password_free(raw);
        }
        return fail(ErrorCode::KeyNotFound, msg);
    }
    if (raw == nullptr) {
        return fail(ErrorCode::KeyNotFound,
                    "profile key is missing in OS vault; run 'kasumi key "
                    "<profile>' to re-enter the key");
    }
    std::string hex{raw};
    crypto_wipe(raw, std::strlen(raw));
    secret.password_free(raw);
    StringWiper wiper{hex};
    return decode_obscured_hex(hex);
}

std::expected<void, runtime::Error>
secret_service_write(const std::string& target, const KeyBytes& clear_key) {
    const auto& secret = SecretApi::instance();
    if (!secret.loaded) {
        return fail(ErrorCode::KeyWriteFailure,
                    "libsecret-1.so.0 is not available on this system");
    }
    std::string hex = encode_obscured_hex(clear_key);
    StringWiper wiper{hex};
    SecretApi::GError* err = nullptr;
    const int stored = secret.store_sync(SecretApi::schema(),
                                         "default",
                                         target.c_str(),
                                         hex.c_str(),
                                         nullptr,
                                         &err,
                                         "target",
                                         target.c_str(),
                                         static_cast<const char*>(nullptr));
    if (err != nullptr) {
        std::string msg =
            err->message != nullptr ? err->message : "Secret Service error";
        secret.error_free(err);
        return fail(ErrorCode::KeyWriteFailure, msg);
    }
    if (stored == 0) {
        return fail(ErrorCode::KeyWriteFailure,
                    "failed to store key in Freedesktop Secret Service");
    }
    return {};
}

std::expected<void, runtime::Error>
secret_service_delete(const std::string& target) {
    const auto& secret = SecretApi::instance();
    if (!secret.loaded) {
        return {};
    }
    SecretApi::GError* err = nullptr;
    static_cast<void>(secret.clear_sync(SecretApi::schema(),
                                        nullptr,
                                        &err,
                                        "target",
                                        target.c_str(),
                                        static_cast<const char*>(nullptr)));
    if (err != nullptr) {
        std::string msg =
            err->message != nullptr ? err->message : "Secret Service error";
        secret.error_free(err);
        return fail(ErrorCode::IoFailure, msg);
    }
    return {};
}

enum class LinuxBackend {
    None,
    SecretService,
    KWallet,
};

LinuxBackend select_linux_backend(std::string& reason) {
    if (!has_session_dbus()) {
        reason = "no active D-Bus session bus for OS credential vault";
        return LinuxBackend::None;
    }
    if (const char* override_env = std::getenv("KASUMI_LINUX_VAULT_BACKEND")) {
        const std::string_view mode{override_env};
        if (mode == "secret-service") {
            return LinuxBackend::SecretService;
        }
        if (mode == "kwallet") {
            return LinuxBackend::KWallet;
        }
        if (!mode.empty() && mode != "auto") {
            reason = "invalid KASUMI_LINUX_VAULT_BACKEND value";
            return LinuxBackend::None;
        }
    }

    const auto& dbus = DbusApi::instance();
    if (!dbus.loaded) {
        if (SecretApi::instance().loaded) {
            return LinuxBackend::SecretService;
        }
        reason = "neither libdbus-1.so.3 nor libsecret-1.so.0 is available";
        return LinuxBackend::None;
    }

    auto conn_res = connect_session_dbus(dbus, ErrorCode::KeyNotFound);
    if (!conn_res) {
        reason = conn_res.error().detail;
        return LinuxBackend::None;
    }
    DbusConnGuard conn{dbus, *conn_res};

    const bool prefer_kde = desktop_prefers_kde();
    const bool secret_loaded = SecretApi::instance().loaded;
    const bool secret_owned =
        secret_loaded &&
        dbus_name_has_owner(dbus, conn.conn, "org.freedesktop.secrets");
    bool kwallet_owned = false;
    for (const auto& ep : kKWalletEndpoints) {
        if (dbus_name_has_owner(dbus, conn.conn, ep.service)) {
            kwallet_owned = true;
            break;
        }
    }
    if (prefer_kde) {
        if (kwallet_owned) {
            return LinuxBackend::KWallet;
        }
        if (secret_owned) {
            return LinuxBackend::SecretService;
        }
    } else {
        if (secret_owned) {
            return LinuxBackend::SecretService;
        }
        if (kwallet_owned) {
            return LinuxBackend::KWallet;
        }
    }

    const bool secret_act =
        secret_loaded &&
        dbus_name_activatable(dbus, conn.conn, "org.freedesktop.secrets");
    bool kwallet_act = false;
    for (const auto& ep : kKWalletEndpoints) {
        if (dbus_name_activatable(dbus, conn.conn, ep.service)) {
            kwallet_act = true;
            break;
        }
    }
    if (prefer_kde) {
        if (kwallet_act) {
            return LinuxBackend::KWallet;
        }
        if (secret_act) {
            return LinuxBackend::SecretService;
        }
    } else {
        if (secret_act) {
            return LinuxBackend::SecretService;
        }
        if (kwallet_act) {
            return LinuxBackend::KWallet;
        }
    }

    reason = "no OS credential vault service (Secret Service or KDE Wallet) "
             "available in current session";
    return LinuxBackend::None;
}
#endif

} // namespace

std::expected<KeyBytes, runtime::Error>
read_vault(const std::filesystem::path& key_path) {
#if defined(_WIN32)
    const auto target = vault_target_name(key_path);
    PCREDENTIALW cred = nullptr;
    const auto error = credential_call([&] {
        return CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &cred);
    });
    if (error == ERROR_NOT_FOUND) {
        return fail(ErrorCode::KeyNotFound,
                    "profile key is missing in OS vault; run 'kasumi key "
                    "<profile>' to re-enter the key");
    }
    if (error != ERROR_SUCCESS) {
        return fail(ErrorCode::IoFailure, credential_error("read key", error));
    }
    struct CredGuard {
        PCREDENTIALW ptr;
        ~CredGuard() noexcept {
            if (ptr != nullptr) {
                if (ptr->CredentialBlob != nullptr &&
                    ptr->CredentialBlobSize > 0) {
                    crypto_wipe(ptr->CredentialBlob, ptr->CredentialBlobSize);
                }
                CredFree(ptr);
            }
        }
    } cred_guard{cred};

    if (cred->CredentialBlob == nullptr ||
        cred->CredentialBlobSize != static_cast<DWORD>(KEY_SIZE)) {
        return fail(ErrorCode::KeyInvalid, "OS vault key has invalid size");
    }
    KeyBytes key{};
    WipeGuard guard{key};
    std::memcpy(key.data(), cred->CredentialBlob, KEY_SIZE);
    obscure(key);
    return key;
#elif defined(__linux__)
    std::string reason;
    const auto backend = select_linux_backend(reason);
    const auto target = linux_vault_target_name(key_path);
    if (backend == LinuxBackend::SecretService) {
        return secret_service_read(target);
    }
    if (backend == LinuxBackend::KWallet) {
        return kwallet_read(target);
    }
    return fail(ErrorCode::KeyNotFound, std::move(reason));
#else
    static_cast<void>(key_path);
    return fail(ErrorCode::KeyNotFound,
                "OS credential vault is not supported on this platform yet");
#endif
}

std::expected<void, runtime::Error>
write_vault(const std::filesystem::path& key_path, const KeyBytes& clear_key) {
#if defined(_WIN32)
    auto target = vault_target_name(key_path);
    KeyBytes stored = clear_key;
    obscure(stored);
    WipeGuard guard{stored};

    CREDENTIALW cred{};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = target.data();
    cred.CredentialBlobSize = static_cast<DWORD>(stored.size());
    cred.CredentialBlob = stored.data();
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

    const auto error = credential_call([&] {
        return CredWriteW(&cred, 0);
    });
    if (error != ERROR_SUCCESS) {
        return fail(ErrorCode::KeyWriteFailure,
                    credential_error("store key", error));
    }
    return {};
#elif defined(__linux__)
    std::string reason;
    const auto backend = select_linux_backend(reason);
    const auto target = linux_vault_target_name(key_path);
    if (backend == LinuxBackend::SecretService) {
        return secret_service_write(target, clear_key);
    }
    if (backend == LinuxBackend::KWallet) {
        return kwallet_write(target, clear_key);
    }
    return fail(ErrorCode::KeyWriteFailure, std::move(reason));
#else
    static_cast<void>(key_path);
    static_cast<void>(clear_key);
    return fail(ErrorCode::KeyWriteFailure,
                "OS credential vault is not supported on this platform yet");
#endif
}

std::expected<void, runtime::Error>
delete_vault(const std::filesystem::path& key_path) {
#if defined(_WIN32)
    const auto target = vault_target_name(key_path);
    const auto error = credential_call([&] {
        return CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0);
    });
    if (error != ERROR_SUCCESS && error != ERROR_NOT_FOUND) {
        return fail(ErrorCode::IoFailure,
                    credential_error("delete key", error));
    }
    return {};
#elif defined(__linux__)
    std::string reason;
    const auto backend = select_linux_backend(reason);
    if (backend == LinuxBackend::None) {
        return {};
    }
    const auto target = linux_vault_target_name(key_path);
    if (backend == LinuxBackend::SecretService) {
        return secret_service_delete(target);
    }
    if (backend == LinuxBackend::KWallet) {
        return kwallet_delete(target);
    }
    return {};
#else
    static_cast<void>(key_path);
    return {};
#endif
}

std::expected<KeyBytes, runtime::Error> derive(std::string_view password,
                                               std::string_view salt_password) {
    if (password.size() < MINIMUM_PASSWORD_SIZE ||
        salt_password.size() < MINIMUM_PASSWORD_SALT_SIZE ||
        password.size() > std::numeric_limits<std::uint32_t>::max() ||
        salt_password.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = ErrorCode::KeyDerivationFailure,
            .detail = "password must be at least 12 characters and salt must "
                      "be at least 16 characters"});
    }
    crypto_argon2_config config = {.algorithm = CRYPTO_ARGON2_ID,
                                   .nb_blocks = ARGON2_MEMORY_BLOCKS,
                                   .nb_passes = ARGON2_PASSES,
                                   .nb_lanes = 1};

    void* work_area = std::malloc(config.nb_blocks * 1024);
    if (!work_area) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyDerivationFailure,
                  .detail = "memory allocation failed in Argon2"});
    }

    crypto_argon2_inputs inputs = {
        .pass = reinterpret_cast<const uint8_t*>(password.data()),
        .salt = reinterpret_cast<const uint8_t*>(salt_password.data()),
        .pass_size = static_cast<uint32_t>(password.size()),
        .salt_size = static_cast<uint32_t>(salt_password.size())};

    KeyBytes key{};
    WipeGuard key_guard{key};
    crypto_argon2(key.data(),
                  KEY_SIZE,
                  work_area,
                  config,
                  inputs,
                  crypto_argon2_no_extras);

    crypto_wipe(work_area, config.nb_blocks * 1024);
    std::free(work_area);
    return key;
}

} // namespace kasumi::runtime::vault
