#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "application/use_cases/context.hpp"
#include "platform/path.hpp"
#include "runtime/vault.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"
#include "process_crash_test_hook.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

#if defined(_WIN32)
#include <cstdlib>
#endif

namespace kasumi::application::detail {
std::expected<Response, Error> run_sync(OperationContext& context);
}

namespace {

std::string environment(const char* name) {
#if defined(_WIN32)
    const auto* value = _wgetenv(std::filesystem::path{name}.wstring().c_str());
    if (value == nullptr) {
        return {};
    }
    return kasumi::platform::path::to_utf8(std::filesystem::path{value});
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string{value};
#endif
}

std::filesystem::path environment_path(const char* name) {
#if defined(_WIN32)
    const auto wide_name = std::filesystem::path{name}.wstring();
    const auto* value = _wgetenv(wide_name.c_str());
    return value == nullptr ? std::filesystem::path{}
                            : std::filesystem::path{value};
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::filesystem::path{}
                            : std::filesystem::path{value};
#endif
}

kasumi::transport::Transport crash_storage(kasumi::transport::Transport& base) {
    using namespace kasumi::transport;
    return Transport{
        .state = TransportStateHandle{&base, [](void*) noexcept {}},
        .storage = StorageOperations{
            .initialize = [](void* state) {
                return initialize(*static_cast<Transport*>(state));
            },
            .put = [](void* state, const std::filesystem::path& source,
                      std::string_view identifier) {
                auto result = put(*static_cast<Transport*>(state), source,
                                  identifier);
                if (result) {
                    kasumi::platform::process_crash_test_hook::pause_at(
                        "transport.put", identifier);
                }
                return result;
            },
            .get = [](void* state, std::string_view identifier,
                      const std::filesystem::path& destination) {
                return get(*static_cast<Transport*>(state), identifier,
                           destination);
            },
            .presence = [](void* state, std::string_view identifier) {
                return presence(*static_cast<Transport*>(state), identifier);
            },
            .list = [](void* state) {
                return list(*static_cast<Transport*>(state));
            },
            .list_prefix = [](void* state, std::string_view prefix) {
                return list(*static_cast<Transport*>(state), prefix);
            },
            .remove = [](void* state, std::string_view identifier) {
                auto result = remove(*static_cast<Transport*>(state), identifier);
                if (result && *result == Removal::Removed) {
                    kasumi::platform::process_crash_test_hook::pause_at(
                        "transport.remove", identifier);
                }
                return result;
            },
        },
    };
}

} // namespace

int main() {
    const auto mode = environment("KASUMI_CRASH_TEST_MODE");
    const auto profile = environment_path("KASUMI_CRASH_TEST_PROFILE");
    const auto local = environment_path("KASUMI_CRASH_TEST_LOCAL");
    const auto remote = environment_path("KASUMI_CRASH_TEST_STORAGE");
    if ((mode != "sync" && mode != "gc") || profile.empty() || local.empty() ||
        remote.empty()) {
        std::cerr << "invalid crash child configuration\n";
        return 2;
    }

    const auto location = kasumi::platform::path::to_utf8(remote);
    auto opened = kasumi::transport::open_transport(location);
    if (!opened) {
        std::cerr << "could not open persistent local transport: "
                  << opened.error().message << '\n';
        return 3;
    }
    if (auto initialized = kasumi::transport::initialize(*opened);
        !initialized) {
        std::cerr << "could not initialize persistent local transport: "
                  << initialized.error().message << '\n';
        return 4;
    }

    kasumi::runtime::vault::KeyBytes key{};
    for (std::size_t index = 0; index < key.size(); ++index) {
        key[index] = static_cast<std::uint8_t>(index + 1U);
    }
    kasumi::runtime::RuntimeData runtime{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location = location,
    };
    auto storage = crash_storage(*opened);

    if (mode == "sync") {
        kasumi::application::detail::OperationContext context{
            .operation = kasumi::application::Operation::Sync,
            .runtime = runtime,
            .summary = {.local_dir = local, .remote_dir = location},
            .key = key,
            .storage = std::move(storage),
        };
        auto result = kasumi::application::detail::run_sync(context);
        if (!result) {
            std::cerr << "child Sync failed before crash point: "
                      << result.error().detail << '\n';
            return 5;
        }
        return 0;
    }

    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key);
    auto result = kasumi::application::integrity::garbage_collect(
        runtime, storage, key,
        [&](const kasumi::application::GarbageCollectProgress& progress) {
            if (progress.stage == kasumi::application::GarbageCollectStage::Analyzing) {
                kasumi::platform::process_crash_test_hook::pause_at(
                    "gc.barrier.acquired", layout.barrier_identifier);
            }
        });
    if (!result) {
        std::cerr << "child GC failed before crash point: "
                  << result.error().detail << '\n';
        return 6;
    }
    return 0;
}
