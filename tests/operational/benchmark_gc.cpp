#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "crypto/file_crypto.hpp"
#include "gc_live_preflight_support.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "runtime/vault.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <psapi.h>
// clang-format on
#else
#include <sys/resource.h>
#endif

namespace {
namespace app = kasumi::application;
namespace history = app::history_storage;
namespace trace = kasumi::platform::perf_trace;
namespace transport = kasumi::transport;
namespace live = kasumi::operational::gc_live_preflight;
namespace smoke = kasumi::operational::remote_copy_smoke;
using Clock = std::chrono::steady_clock;
using Json = nlohmann::json;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::uint64_t elapsed_us(Clock::time_point started) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() -
                                                              started)
            .count());
}

Json peak_rss_kib() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS counters{};
    if (GetProcessMemoryInfo(
            GetCurrentProcess(), &counters, sizeof(counters))) {
        return counters.PeakWorkingSetSize / 1024;
    }
#else
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#ifdef __APPLE__
        return usage.ru_maxrss / 1024;
#else
        return usage.ru_maxrss;
#endif
    }
#endif
    return nullptr;
}

void write_file(const std::filesystem::path& path, std::string_view bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.close();
    require(static_cast<bool>(output), "fixture file write failed");
}

void save_report(const std::filesystem::path& workspace, const Json& report) {
    write_file(workspace / "result.json", report.dump(2) + "\n");
}

int run(int argc, char** argv) {
    std::filesystem::path workspace;
    std::optional<smoke::RemoteParent> parent;
    std::size_t candidates = 0;
    bool count_set = false, confirmed = false, large_confirmed = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view option{argv[index]};
        if (option == "--confirm-disposable-parent") {
            confirmed = true;
        } else if (option == "--confirm-large-remote") {
            large_confirmed = true;
        } else {
            require(index + 1 < argc, "missing argument value");
            const std::string_view value{argv[++index]};
            if (option == "--workspace" && workspace.empty()) {
                workspace = kasumi::platform::path::from_utf8(value);
            } else if (option == "--candidates" && !count_set) {
                const auto parsed = std::from_chars(
                    value.data(), value.data() + value.size(), candidates);
                require(parsed.ec == std::errc{} &&
                            parsed.ptr == value.data() + value.size() &&
                            candidates <= 20000,
                        "candidates must be an integer from 0 to 20000");
                count_set = true;
            } else if (option == "--remote-parent" && !parent) {
                auto parsed = smoke::parse_remote_parent(value);
                require(parsed.has_value() &&
                            value.find_first_of("<>") == std::string_view::npos,
                        "remote parent must be a concrete subdirectory");
                std::string lower = parsed->directory;
                std::ranges::transform(
                    lower, lower.begin(), [](unsigned char c) {
                        return static_cast<char>(std::tolower(c));
                    });
                for (const auto& component : std::filesystem::path(lower)) {
                    require(component != "programming",
                            "production Programming vault is forbidden");
                }
                parent = std::move(*parsed);
            } else {
                throw std::runtime_error("unknown or duplicate argument");
            }
        }
    }
    require(!workspace.empty() && count_set,
            "--workspace and --candidates are required");
    require(!parent || confirmed,
            "remote writes require --confirm-disposable-parent");
    require(!parent || candidates < 20000 || large_confirmed,
            "20000 remote candidates require --confirm-large-remote after "
            "reviewing provider costs");
    workspace = std::filesystem::absolute(workspace).lexically_normal();
    require(std::filesystem::create_directory(workspace),
            "workspace must be a new directory");
    require(kasumi::platform::private_storage::protect_directory(workspace)
                .has_value(),
            "could not protect isolated workspace");
    Json report{{"schema", 1},
                {"backend", parent ? "rclone" : "local"},
                {"requested_candidates", candidates},
                {"status", "failed"},
                {"stage", "fixture"},
                {"fixture_us", nullptr},
                {"gc_wall_us", nullptr},
                {"fsck_us", nullptr},
                {"cleanup_us", nullptr},
                {"cleanup_confirmed", false},
                {"backend_retries", nullptr}};
    const auto fixture_started = Clock::now();
    bool fixture_complete = false;
    try {
        kasumi::runtime::vault::KeyBytes key{};
        require(kasumi::platform::random::fill_bytes(key).has_value(),
                "key generation failed");
        require(kasumi::runtime::vault::write(workspace / "key.bin", key)
                    .has_value(),
                "test key persistence failed");
        const auto nonce = kasumi::platform::random::hex_id();
        const auto owner = kasumi::platform::random::hex_id();
        require(nonce.has_value() && owner.has_value(),
                "run identifier generation failed");
        std::optional<live::ChildStorage> child;
        std::string location =
            kasumi::platform::path::to_utf8(workspace / "vault");
        if (parent) {
            auto parent_storage = transport::open_transport(parent->location);
            require(parent_storage.has_value(),
                    "remote parent transport could not open");
            const auto name = live::child_namespace(*nonce);
            require(name.has_value(), "invalid generated child namespace");
            const auto pre =
                live::observe_pre_initialize(*parent_storage, *parent, *name);
            report["remote_preflight"] = live::to_json(
                pre, live::classify_pre_initialize(pre, *parent, *name));
            auto opened = live::open_child_storage(*parent, *name);
            require(opened.has_value(), "child transport could not open");
            child = std::move(*opened);
            report["namespace"] = *live::child_location(*parent, *name);
            save_report(workspace, report);
            require(live::initialize_child(*child, pre).has_value(),
                    "remote child was not proven unused");
            const auto post = live::observe_post_initialize(*child);
            require(live::classify_post_initialize(post) ==
                        live::PostInitializeDisposition::Empty,
                    "initialized child is not empty");
            write_file(workspace / "owner.source", *owner);
            require(
                live::establish_ownership_marker(*child,
                                                 post,
                                                 *owner,
                                                 workspace / "owner.source",
                                                 workspace / "owner.readback")
                    .has_value(),
                "benchmark ownership could not be confirmed");
            location = report["namespace"].get<std::string>() + "/vault";
        }
        report["storage"] = location;
        save_report(workspace, report);
        auto opened = transport::open_transport(location);
        require(opened.has_value() &&
                    transport::initialize(*opened).has_value(),
                "vault initialization failed");
        auto& storage = *opened;
        const auto empty = transport::list(storage);
        require(empty.has_value() && empty->empty(),
                "benchmark vault is not empty");
        const auto plain = workspace / "payload.plain";
        const auto cipher = workspace / "payload.cipher";
        const auto put_content = [&](std::string_view contents) {
            write_file(plain, contents);
            std::string error;
            const auto encrypted = kasumi::crypto::encrypt_file_with_hashes(
                plain,
                cipher,
                key,
                kasumi::crypto::FilePurpose::Content,
                &error);
            if (!encrypted) {
                throw std::runtime_error("fixture encryption failed: " + error);
            }
            auto id = kasumi::crypto::content_identifier(
                key, encrypted->plaintext_hash);
            const auto stored = transport::put(storage, cipher, id);
            if (!stored) {
                report["transport_error"] =
                    transport::error_code_name(stored.error().code);
                report["native_code"] = stored.error().native_code;
                report["first_failed_fixture_identifier"] = id;
                report["fixture_mutation_state"] = "Uncertain";
                throw std::runtime_error(
                    "fixture content PUT failed; namespace preserved");
            }
            return id;
        };
        const std::string contents = "protected benchmark content\n";
        const auto live_id = put_content(contents);
        kasumi::Snapshot tree{
            .rows = {
                kasumi::NodeRow{.path = "", .is_directory = true},
                kasumi::NodeRow{.path = "live.txt",
                                .hash = kasumi::hasher::hash_string(contents),
                                .size = contents.size(),
                                .is_directory = false}}};
        kasumi::finalize_snapshot(tree);
        auto commit = kasumi::history::make_commit(0, {}, std::move(tree));
        require(commit.has_value(), "fixture commit creation failed");
        auto published =
            history::publish_commit(storage, key, *commit, workspace);
        require(published.has_value(),
                "authenticated history publication failed");
        const auto layout = history::derive_remote_layout(key);
        std::vector<std::string> protected_ids{
            live_id,
            history::commit_object(layout, published->head),
            history::marker_object(layout, published->head)};
        std::ranges::sort(protected_ids);
        std::vector<std::string> owned = protected_ids;
        for (std::size_t index = 0; index < candidates; ++index) {
            owned.push_back(put_content("orphan-" + std::to_string(index)));
        }
        std::ranges::sort(owned);
        const auto inventory = transport::list(storage);
        require(inventory.has_value(), "fixture inventory failed");
        auto observed = *inventory;
        std::ranges::sort(observed);
        require(observed == owned,
                "fixture inventory contains foreign or missing objects");
        write_file(workspace / "owned-objects.json", Json(owned).dump(2));
        fixture_complete = true;
        report["fixture_us"] = elapsed_us(fixture_started);
        report["fixture_physical_objects"] = owned.size();
        report["fixture_protected_objects"] = protected_ids.size();
        report["peak_rss_before_gc_kib"] = peak_rss_kib();
        report["stage"] = "gc";
        save_report(workspace, report);
        const kasumi::runtime::RuntimeData runtime{
            .local_dir = workspace,
            .database_path = workspace / "unused.sqlite",
            .key_path = workspace / "key.bin",
            .storage_location = location};
        trace::force_enable(true);
        trace::reset();
        app::integrity::GarbageCollectProgressCallback on_progress;
        if (parent) {
            std::optional<app::GarbageCollectStage> last_stage;
            on_progress =
                [last_stage](
                    const app::GarbageCollectProgress& progress) mutable {
                    if (last_stage != progress.stage ||
                        progress.removed_objects % 100 == 0) {
                        last_stage = progress.stage;
                        std::cerr
                            << "GC_PROGRESS stage="
                            << static_cast<int>(progress.stage)
                            << " acknowledged=" << progress.removed_objects
                            << '\n';
                    }
                };
        }
        const auto gc_started = Clock::now();
        const auto result = app::integrity::garbage_collect(
            runtime, storage, key, std::move(on_progress));
        report["gc_wall_us"] = elapsed_us(gc_started);
        report["peak_rss_after_gc_kib"] = peak_rss_kib();
        trace::report(result ? "success" : "failure");
        trace::force_enable(false);
        if (!result) {
            report["gc_error"] = true;
            if (result.error().transport_failure) {
                report["transport_error"] = transport::error_code_name(
                    result.error().transport_failure->code);
                report["native_code"] =
                    result.error().transport_failure->native_code;
            }
            if (const auto& diagnostic = result.error().garbage_collection;
                diagnostic) {
                report["confirmed_removed"] = diagnostic->confirmed_removed;
                report["first_failed_identifier"] =
                    diagnostic->failed_identifier
                        ? Json(*diagnostic->failed_identifier)
                        : Json(nullptr);
                report["mutation_state"] =
                    static_cast<int>(diagnostic->mutation_state);
                report["barrier_release_confirmed"] =
                    diagnostic->barrier_release_confirmed;
                report["barrier_cleanup_failed"] =
                    diagnostic->barrier_cleanup_error.has_value();
                if (diagnostic->barrier_cleanup_transport_error) {
                    report["cleanup_transport_error"] =
                        transport::error_code_name(
                            diagnostic->barrier_cleanup_transport_error->code);
                    report["cleanup_native_code"] =
                        diagnostic->barrier_cleanup_transport_error
                            ->native_code;
                }
                if (diagnostic->transport_error) {
                    report["transport_error"] = transport::error_code_name(
                        diagnostic->transport_error->code);
                    report["native_code"] =
                        diagnostic->transport_error->native_code;
                }
            }
        }
        require(result.has_value() && !result->analysis_only &&
                    result->removed_objects == candidates,
                "GC did not acknowledge the complete fixture plan; evidence "
                "preserved");
        report["confirmed_removed"] = result->removed_objects;
        report["stage"] = "fsck";
        const auto fsck_started = Clock::now();
        const auto audited = app::integrity::fsck(runtime, storage, key);
        report["fsck_us"] = elapsed_us(fsck_started);
        require(audited.has_value(), "post-GC FSCK failed; evidence preserved");
        report["fsck_passed"] = true;
        report["stage"] = "cleanup";
        const auto cleanup_started = Clock::now();
        auto remaining = transport::list(storage);
        require(remaining.has_value(),
                "cleanup inventory failed; evidence preserved");
        std::ranges::sort(*remaining);
        require(*remaining == protected_ids,
                "unexpected residue; cleanup refused");
        if (child) {
            std::vector<std::string> cleanup_ids;
            for (const auto& id : protected_ids) {
                cleanup_ids.push_back("vault/" + id);
            }
            const auto cleanup = live::cleanup_owned_child(
                *child, *owner, cleanup_ids, workspace);
            report["cleanup"] = live::to_json(cleanup);
            require(cleanup.result == "removed",
                    "owned cleanup unconfirmed; preserve namespace");
        } else {
            for (const auto& id : protected_ids) {
                require(transport::remove(storage, id).has_value(),
                        "local cleanup failed");
            }
            const auto residue = transport::list(storage);
            require(residue.has_value() && residue->empty(),
                    "local cleanup is unconfirmed");
        }
        report["cleanup_us"] = elapsed_us(cleanup_started);
        report["cleanup_confirmed"] = true;
        report["stage"] = "complete";
        report["status"] = "success";
    } catch (const std::exception& error) {
        if (!fixture_complete) {
            report["fixture_us"] = elapsed_us(fixture_started);
        }
        report["error"] = error.what();
    }
    save_report(workspace, report);
    std::cout << "GC_BENCHMARK " << report.dump() << '\n';
    return report["status"] == "success" ? 0 : 1;
}
} // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "GC benchmark refused: " << error.what() << '\n';
        return 2;
    }
}
