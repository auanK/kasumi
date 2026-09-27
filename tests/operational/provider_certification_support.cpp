#include "provider_certification_support.hpp"

#include "application/execute.hpp"
#include "application/integrity/maintenance.hpp"
#include "application/observation/history.hpp"
#include "application/profile.hpp"
#include "core/hasher.hpp"
#include "crypto/key_derivation.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/provider_scenarios.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <iterator>
#include <random>
#include <stdexcept>
#include <system_error>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace kasumi::operational::provider_certification {
namespace {

constexpr std::string_view owner_file = ".kasumi-certification-owner";
constexpr std::string_view master_hex =
    "7777777777777777777777777777777777777777777777777777777777777777";
constexpr std::string_view demo_payload = "provider-certification-payload";

std::string unique_token() {
    std::random_device random;
    return std::to_string(random()) + "-" +
           std::to_string(
               std::chrono::steady_clock::now().time_since_epoch().count());
}

bool direct_child(const std::filesystem::path& parent,
                  const std::filesystem::path& child) {
    const auto relative = child.lexically_relative(parent);
    if (relative.empty() || relative == "." || relative.is_absolute() ||
        relative.has_root_name() || relative.has_root_directory()) {
        return false;
    }
    auto it = relative.begin();
    if (it == relative.end() || *it == "..") {
        return false;
    }
    ++it;
    return it == relative.end();
}

bool is_reparse_or_symlink(const std::filesystem::path& path,
                           const std::filesystem::file_status& status) {
    if (std::filesystem::is_symlink(status))
        return true;
#if defined(_WIN32)
    const auto attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    (void)path;
    return false;
#endif
}

std::expected<void, std::string>
reject_reparse_tree(const std::filesystem::path& root) {
    std::error_code error;
    for (std::filesystem::recursive_directory_iterator
             it(root, std::filesystem::directory_options::none, error),
         end;
         it != end;
         it.increment(error)) {
        if (error)
            return std::unexpected(error.message());
        const auto status = it->symlink_status(error);
        if (error)
            return std::unexpected(error.message());
        if (is_reparse_or_symlink(it->path(), status)) {
            it.disable_recursion_pending();
            return std::unexpected(
                "refusing cleanup: target contains a symlink or reparse point");
        }
    }
    if (error)
        return std::unexpected(error.message());
    return {};
}

std::string platform_name() {
#if defined(_WIN32)
    return "Windows";
#elif defined(__linux__)
    return "Linux";
#elif defined(__APPLE__)
    return "macOS";
#else
    return "unknown";
#endif
}

std::expected<void, std::string>
make_directory(const std::filesystem::path& p) {
    std::error_code error;
    std::filesystem::create_directories(p, error);
    if (error) {
        return std::unexpected(error.message());
    }
    return {};
}

std::expected<void, std::string>
create_profile(const application::ExecutionEnvironment& environment,
               std::string name,
               const std::filesystem::path& local,
               const std::filesystem::path& remote) {
    auto local_result = make_directory(local);
    if (!local_result) {
        return local_result;
    }
    const auto result = application::create_profile(
        environment,
        application::Profile{.name = std::move(name),
                             .local_dir = local,
                             .remote_dir = platform::path::to_utf8(remote)},
        application::MasterKeyHex{std::string{master_hex}});
    if (!result) {
        return std::unexpected(result.error().detail);
    }
    return {};
}

std::expected<application::Response, application::Error>
execute(const application::ExecutionEnvironment& environment,
        std::string_view profile,
        application::Operation operation) {
    const auto result = application::execute(
        {application::Request{operation, std::string{profile}},
         application::Credentials{application::NoCredentials{}},
         environment});
    if (!result)
        return std::unexpected(result.error());
    return *result;
}

runtime::RuntimeData runtime_data(const std::filesystem::path& app_data,
                                  std::string_view profile) {
    auto result =
        runtime::resolve(app_data, profile, runtime::AccessMode::ReadOnly);
    if (!result) {
        throw std::runtime_error(result.error().detail);
    }
    return *result;
}

void add_scenario(Report& report,
                  std::string label,
                  bool passed,
                  std::string diagnostic = {}) {
    Scenario result{.name = std::move(label),
                    .status =
                        passed ? ScenarioStatus::Pass : ScenarioStatus::Fail};
    if (!diagnostic.empty()) {
        result.diagnostics.push_back(std::move(diagnostic));
    }
    report.scenarios.push_back(std::move(result));
}

void record_trace(Scenario& scenario) {
    constexpr std::array metrics{
        "transport list",
        "transport list prefix",
        "sync content presence requests",
        "commit.individual_get_calls",
        "commit.get_batch_calls",
        "commit.get_batch_objects",
        "marker.get_calls",
        "epoch.get_calls",
        "fsck.audit_get_calls",
        "fsck.audit_decrypt_calls",
        "fsck.audit_verify_calls",
    };
    for (const auto* metric : metrics) {
        const auto value = platform::perf_trace::get_count(metric);
        if (value != 0) {
            scenario.requests.emplace(metric, value);
        }
    }
}

void record_direct(Report& report, std::string_view operation) {
    ++report.harness_requests[std::string{operation}];
}

std::expected<transport::Transport, std::string>
open_storage(const std::filesystem::path& root) {
    auto result = transport::open_transport(platform::path::to_utf8(root));
    if (!result) {
        return std::unexpected(transport::describe(result.error()));
    }
    if (auto initialized = transport::initialize(*result); !initialized) {
        return std::unexpected(transport::describe(initialized.error()));
    }
    return std::move(*result);
}

std::string content_id(const crypto::Key& key, std::string_view plaintext) {
    return crypto::content_identifier(key, hasher::hash_string(plaintext));
}

std::expected<std::vector<std::uint8_t>, std::string>
read_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected("could not open evidence file");
    }
    return std::vector<std::uint8_t>{std::istreambuf_iterator<char>{input},
                                     std::istreambuf_iterator<char>{}};
}

bool write_bytes(const std::filesystem::path& path,
                 const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    return output.good();
}

std::expected<std::optional<state_storage::StoredState>, std::string>
load_state(const std::filesystem::path& app_data, std::string_view profile) {
    const auto runtime = runtime_data(app_data, profile);
    return state_storage::load_state(runtime.database_path);
}

bool has_file(const std::filesystem::path& root,
              std::string_view relative,
              std::string_view expected) {
    std::error_code error;
    const auto path = root / platform::path::from_utf8(relative);
    return std::filesystem::is_regular_file(path, error) && !error &&
           test::read_text(path) == expected;
}

Capability capability(std::string key, bool present, std::string detail = {}) {
    return Capability{.name = std::move(key),
                      .status = present ? CapabilityStatus::Supported
                                        : CapabilityStatus::Unsupported,
                      .detail = std::move(detail)};
}

void characterize_capabilities(Report& report,
                               transport::Transport& storage,
                               const std::filesystem::path& workspace) {
    const auto round_trip =
        test::scenarios::transport_round_trip(storage, workspace);
    for (const auto& [operation, count] : round_trip.requests) {
        report.harness_requests[operation] += count;
    }
    Scenario round_trip_result{.name = "transport-round-trip",
                               .status = round_trip.passed
                                             ? ScenarioStatus::Pass
                                             : ScenarioStatus::Fail,
                               .diagnostics = round_trip.diagnostics};
    report.scenarios.push_back(std::move(round_trip_result));

    const auto& ops = storage.storage;
    const auto required = [&](std::string key, bool exposed) {
        auto item = capability(std::move(key), exposed && round_trip.passed);
        if (!exposed || !round_trip.passed) {
            item.status = CapabilityStatus::Failed;
            item.error = transport::ErrorCode::Unknown;
            item.detail =
                "required round-trip operation failed or was unavailable";
        } else {
            item.detail = "exercised by shared transport-round-trip scenario";
        }
        report.capabilities.push_back(std::move(item));
    };
    required("put", ops.put != nullptr);
    required("get", ops.get != nullptr);
    required("presence", ops.presence != nullptr);
    required("list", ops.list != nullptr);
    required("remove", ops.remove != nullptr);
    report.capabilities.push_back(capability("copy", ops.copy != nullptr));
    report.capabilities.push_back(
        capability("list_prefix", ops.list_prefix != nullptr));
    report.capabilities.push_back(
        capability("put_batch_native", ops.put_batch != nullptr));
    report.capabilities.push_back(
        capability("put_files_batch", ops.put_files_batch != nullptr));
    report.capabilities.push_back(
        capability("get_batch_native", ops.get_batch != nullptr));
    report.capabilities.push_back(
        capability("copy_batch", ops.copy_batch != nullptr));
    report.capabilities.push_back(
        capability("remove_batch", ops.remove_batch != nullptr));
    report.capabilities.push_back(
        capability("physical_hash", ops.physical_hash != nullptr));
    report.capabilities.push_back(
        capability("physical_hash_batch", ops.physical_hash_batch != nullptr));
    report.capabilities.push_back(
        capability("control_read_batch", ops.control_read_batch != nullptr));

    const auto fail_optional = [&](std::string_view name_value,
                                   std::string detail) {
        auto item = std::ranges::find(
            report.capabilities, name_value, &Capability::name);
        if (item != report.capabilities.end()) {
            item->status = CapabilityStatus::Failed;
            item->error = transport::ErrorCode::Unknown;
            item->detail = std::move(detail);
        }
    };
    if (ops.copy != nullptr) {
        const auto source = workspace / "capability-copy-source";
        const auto destination = workspace / "capability-copy-destination";
        test::write_text(source, "copy-capability");
        const auto put = transport::put(storage, source, "capability/source");
        record_direct(report, "put");
        const auto copy = transport::copy(
            storage, "capability/source", "capability/destination");
        record_direct(report, "copy");
        const auto get =
            transport::get(storage, "capability/destination", destination);
        record_direct(report, "get");
        const auto source_present =
            transport::presence(storage, "capability/source");
        record_direct(report, "presence");
        const bool valid = put && copy && get && source_present &&
                           *source_present == transport::Presence::Present &&
                           test::read_text(destination) == "copy-capability";
        const auto remove_destination =
            transport::remove(storage, "capability/destination");
        record_direct(report, "remove");
        const auto remove_source =
            transport::remove(storage, "capability/source");
        record_direct(report, "remove");
        if (!valid || !remove_destination || !remove_source) {
            fail_optional(
                "copy", "Local copy capability did not preserve source bytes");
        } else {
            std::ranges::find(
                report.capabilities, std::string{"copy"}, &Capability::name)
                ->detail =
                "exercised; verified destination bytes and source retention";
        }
    }
    if (ops.list_prefix != nullptr) {
        const auto source = workspace / "capability-prefix-source";
        test::write_text(source, "prefix-capability");
        const auto put =
            transport::put(storage, source, "capabilities/prefix/item");
        record_direct(report, "put");
        const auto listing = transport::list(storage, "capabilities/prefix");
        record_direct(report, "list_prefix");
        const bool valid =
            put && listing && *listing == std::vector<std::string>{"item"};
        const auto removed =
            transport::remove(storage, "capabilities/prefix/item");
        record_direct(report, "remove");
        if (!valid || !removed) {
            fail_optional(
                "list_prefix",
                "Local prefix listing did not return the direct child");
        } else {
            std::ranges::find(report.capabilities,
                              std::string{"list_prefix"},
                              &Capability::name)
                ->detail = "exercised; returned only the direct child";
        }
    }
    for (auto& item : report.capabilities) {
        if (item.status == CapabilityStatus::Unsupported) {
            item.detail =
                "optional operation is not exposed by Local transport";
        }
    }
}

} // namespace

std::string_view name(CapabilityStatus status) noexcept {
    switch (status) {
        case CapabilityStatus::Supported:
            return "Supported";
        case CapabilityStatus::Unsupported:
            return "Unsupported";
        case CapabilityStatus::Failed:
            return "Failed";
    }
    return "Failed";
}

std::string_view name(ScenarioStatus status) noexcept {
    switch (status) {
        case ScenarioStatus::Pass:
            return "Pass";
        case ScenarioStatus::Fail:
            return "Fail";
        case ScenarioStatus::Blocked:
            return "Blocked";
        case ScenarioStatus::NotRun:
            return "NotRun";
    }
    return "NotRun";
}

std::string derive_status(const Report& report) {
    if (!report.diagnostics.empty() || report.cleanup == "FAILED" ||
        std::ranges::any_of(report.capabilities,
                            [](const auto& item) {
                                return item.status == CapabilityStatus::Failed;
                            }) ||
        std::ranges::any_of(report.scenarios, [](const auto& item) {
            return item.status == ScenarioStatus::Fail ||
                   item.status == ScenarioStatus::Blocked;
        })) {
        return "FAIL";
    }
    return "PASS";
}

std::expected<LocalTarget, std::string>
create_local_target(const std::filesystem::path& authorized_parent) {
    std::error_code error;
    const auto parent = std::filesystem::canonical(authorized_parent, error);
    if (error || !std::filesystem::is_directory(parent)) {
        return std::unexpected(
            "authorized temp parent must exist and be a directory");
    }
    constexpr std::size_t attempts = 32;
    for (std::size_t attempt = 0; attempt < attempts; ++attempt) {
        const auto token = unique_token();
        const auto root = parent / ("kasumi-cert-" + token);
        if (!std::filesystem::create_directory(root, error)) {
            if (error) {
                return std::unexpected(error.message());
            }
            continue;
        }
        const auto marker = root / owner_file;
        std::ofstream output(marker, std::ios::binary | std::ios::out);
        output << token;
        output.close();
        if (!output) {
            std::filesystem::remove(root, error);
            return std::unexpected(
                "could not persist local target ownership marker");
        }
        return LocalTarget{.authorized_parent = parent,
                           .root = root,
                           .ownership_token = token};
    }
    return std::unexpected("could not create unique local target child");
}

std::expected<std::filesystem::path, std::string>
target_path(const LocalTarget& target, const std::filesystem::path& relative) {
    if (relative.empty() || relative.is_absolute() ||
        relative.has_root_name() || relative.has_root_directory()) {
        return std::unexpected("target path must be non-empty and relative");
    }
    for (const auto& component : relative) {
        if (component == ".." || component == ".") {
            return std::unexpected("target path contains traversal");
        }
    }
    const auto candidate = (target.root / relative).lexically_normal();
    const auto within = candidate.lexically_relative(target.root);
    if (within.empty() || within.is_absolute() || within.has_root_name() ||
        within.has_root_directory() ||
        (within.begin() != within.end() && *within.begin() == "..")) {
        return std::unexpected("target path escapes owned root");
    }
    auto current = target.root;
    std::error_code error;
    for (const auto& component : relative) {
        current /= component;
        const auto status = std::filesystem::symlink_status(current, error);
        if (error == std::errc::no_such_file_or_directory) {
            error.clear();
            continue;
        }
        if (error)
            return std::unexpected(error.message());
        if (is_reparse_or_symlink(current, status)) {
            return std::unexpected(
                "target path traverses a symlink or reparse point");
        }
    }
    return candidate;
}

std::expected<void, std::string> cleanup_local_target(LocalTarget& target) {
    std::error_code error;
    const auto root_status =
        std::filesystem::symlink_status(target.root, error);
    if (error || !std::filesystem::is_directory(root_status) ||
        std::filesystem::is_symlink(root_status) ||
        !direct_child(target.authorized_parent, target.root)) {
        return std::unexpected(
            "refusing cleanup: target is not the owned direct child");
    }
    const auto canonical_parent =
        std::filesystem::canonical(target.authorized_parent, error);
    if (error || canonical_parent != target.authorized_parent) {
        return std::unexpected("refusing cleanup: authorized parent changed");
    }
    const auto marker = target.root / owner_file;
    const auto marker_status = std::filesystem::symlink_status(marker, error);
    if (error || !std::filesystem::is_regular_file(marker_status) ||
        std::filesystem::is_symlink(marker_status)) {
        return std::unexpected(
            "refusing cleanup: ownership marker is absent or unsafe");
    }
    std::ifstream input(marker, std::ios::binary);
    const std::string token{std::istreambuf_iterator<char>{input},
                            std::istreambuf_iterator<char>{}};
    if (input.bad() || token != target.ownership_token ||
        target.ownership_token.empty()) {
        return std::unexpected(
            "refusing cleanup: ownership marker does not match");
    }
    input.close();
    auto safe_tree = reject_reparse_tree(target.root);
    if (!safe_tree)
        return safe_tree;
    const auto marker_status_after_walk =
        std::filesystem::symlink_status(marker, error);
    if (error || !std::filesystem::is_regular_file(marker_status_after_walk) ||
        is_reparse_or_symlink(marker, marker_status_after_walk)) {
        return std::unexpected("refusing cleanup: ownership marker changed");
    }
    std::ifstream verify_marker(marker, std::ios::binary);
    const std::string verified_token{
        std::istreambuf_iterator<char>{verify_marker},
        std::istreambuf_iterator<char>{}};
    verify_marker.close();
    if (verify_marker.bad() || verified_token != target.ownership_token) {
        return std::unexpected(
            "refusing cleanup: ownership changed before deletion");
    }
    const auto removed = std::filesystem::remove_all(target.root, error);
    if (error || removed == 0) {
        return std::unexpected(error ? error.message()
                                     : "owned target was not removed");
    }
    target.root.clear();
    target.ownership_token.clear();
    return {};
}

Report run_local_certification(const std::filesystem::path& owned_root) {
    Report report{.platform = platform_name(), .target_root = owned_root};
    platform::perf_trace::force_enable(true);
    try {
        const auto app_data = owned_root / "app-data";
        const auto remote = owned_root / "remote";
        const auto test_space = owned_root / "harness";
        auto key = runtime::vault::decode_hex(master_hex);
        if (!key) {
            throw std::runtime_error(key.error().detail);
        }
        std::filesystem::create_directories(app_data);
        std::filesystem::create_directories(test_space);
        const application::ExecutionEnvironment environment{app_data};
        const std::array<std::pair<std::string, std::filesystem::path>, 4>
            clients{{{"a", owned_root / "local-a"},
                     {"b", owned_root / "local-b"},
                     {"c", owned_root / "local-c"},
                     {"repair", owned_root / "local-repair"}}};
        for (const auto& [name_value, local] : clients) {
            auto created =
                create_profile(environment, name_value, local, remote);
            if (!created) {
                throw std::runtime_error(created.error());
            }
        }
        auto opened = open_storage(remote);
        if (!opened) {
            throw std::runtime_error(opened.error());
        }
        auto& storage = *opened;
        characterize_capabilities(report, storage, test_space);

        const std::vector<test::scenarios::SeedFile> files{
            {"a.txt", "alpha"},
            {"b.txt", std::string{demo_payload}},
            {"c.txt", "charlie"}};
        const auto published = test::scenarios::publish_seed_files(
            environment, "a", clients[0].second, files);
        add_scenario(report,
                     "bootstrap-publish",
                     published.has_value(),
                     published ? "" : published.error());
        record_trace(report.scenarios.back());
        const auto second =
            published ? test::scenarios::materialize_files(
                            environment, "b", clients[1].second, files)
                      : std::expected<void, std::string>{
                            std::unexpected("bootstrap was blocked")};
        Scenario second_result{.name = "bootstrap-second-client",
                               .status = second ? ScenarioStatus::Pass
                                                : ScenarioStatus::Fail};
        if (!second)
            second_result.diagnostics.push_back(second.error());
        record_trace(second_result);
        report.scenarios.push_back(std::move(second_result));

        if (!published || !second) {
            for (const auto name_value : {"no-op",
                                          "partial-missing",
                                          "publication-while-missing",
                                          "restore-pending",
                                          "local-source-repair",
                                          "fsck-healthy",
                                          "fsck-missing",
                                          "fsck-corrupt"}) {
                report.scenarios.push_back(Scenario{
                    .name = name_value, .status = ScenarioStatus::Blocked});
            }
        } else {
            const auto no_op = test::scenarios::no_op_sync(environment, "b");
            Scenario no_op_result{.name = "no-op",
                                  .status = no_op && *no_op
                                                ? ScenarioStatus::Pass
                                                : ScenarioStatus::Fail};
            if (!no_op)
                no_op_result.diagnostics.push_back(no_op.error());
            else if (!*no_op)
                no_op_result.diagnostics.push_back(
                    "no-op published, remained partial, or retained pending "
                    "paths");
            record_trace(no_op_result);
            report.scenarios.push_back(std::move(no_op_result));

            const auto object_b = content_id(*key, demo_payload);
            const auto saved_ciphertext = test_space / "saved-b.ciphertext";
            auto saved = transport::get(storage, object_b, saved_ciphertext);
            record_direct(report, "get");
            auto removed = transport::remove(storage, object_b);
            record_direct(report, "remove");
            const auto client_c =
                execute(environment, "c", application::Operation::Sync);
            bool partial_ok =
                saved && removed && client_c &&
                std::holds_alternative<application::SyncCompleted>(
                    client_c->data);
            const application::SyncCompleted* partial = nullptr;
            if (partial_ok) {
                partial = &std::get<application::SyncCompleted>(client_c->data);
                partial_ok =
                    partial->partial && partial->pending_paths.size() == 1 &&
                    platform::path::to_logical_utf8(
                        partial->pending_paths.front()) == "b.txt" &&
                    has_file(clients[2].second, "a.txt", "alpha") &&
                    has_file(clients[2].second, "c.txt", "charlie") &&
                    !std::filesystem::exists(clients[2].second / "b.txt");
            }
            auto state_c = load_state(app_data, "c");
            partial_ok =
                partial_ok && state_c && state_c->has_value() &&
                kasumi::find_row((*state_c)->tree, "b.txt") != nullptr &&
                (*state_c)->pending_materializations.size() == 1;
            Scenario partial_result{.name = "partial-missing",
                                    .status = partial_ok
                                                  ? ScenarioStatus::Pass
                                                  : ScenarioStatus::Fail};
            if (!partial_ok)
                partial_result.diagnostics.emplace_back(
                    "missing ciphertext was not preserved as one pending "
                    "logical reference");
            record_trace(partial_result);
            report.scenarios.push_back(std::move(partial_result));

            test::write_text(clients[2].second / "d.txt", "independent");
            const auto while_missing =
                execute(environment, "c", application::Operation::Sync);
            bool publication_ok =
                while_missing &&
                std::holds_alternative<application::SyncCompleted>(
                    while_missing->data);
            if (publication_ok) {
                const auto& summary =
                    std::get<application::SyncCompleted>(while_missing->data);
                publication_ok = summary.partial && summary.published &&
                                 summary.pending_paths.size() == 1;
            }
            state_c = load_state(app_data, "c");
            publication_ok =
                publication_ok && state_c && state_c->has_value() &&
                kasumi::find_row((*state_c)->tree, "b.txt") != nullptr &&
                kasumi::find_row((*state_c)->tree, "d.txt") != nullptr &&
                (*state_c)->pending_materializations.size() == 1;
            Scenario publication_result{.name = "publication-while-missing",
                                        .status = publication_ok
                                                      ? ScenarioStatus::Pass
                                                      : ScenarioStatus::Fail};
            if (!publication_ok)
                publication_result.diagnostics.emplace_back(
                    "independent D publication lost B or failed to retain "
                    "pending state");
            record_trace(publication_result);
            report.scenarios.push_back(std::move(publication_result));

            const auto restore_put =
                transport::put(storage, saved_ciphertext, object_b);
            record_direct(report, "put");
            const auto restored =
                execute(environment, "c", application::Operation::Sync);
            state_c = load_state(app_data, "c");
            const bool restore_ok =
                restore_put && restored &&
                std::holds_alternative<application::SyncCompleted>(
                    restored->data) &&
                !std::get<application::SyncCompleted>(restored->data).partial &&
                has_file(clients[2].second, "b.txt", demo_payload) && state_c &&
                state_c->has_value() &&
                (*state_c)->pending_materializations.empty();
            Scenario restore_result{.name = "restore-pending",
                                    .status = restore_ok
                                                  ? ScenarioStatus::Pass
                                                  : ScenarioStatus::Fail};
            if (!restore_ok)
                restore_result.diagnostics.emplace_back(
                    "restored ciphertext did not materialize and clear pending "
                    "state");
            record_trace(restore_result);
            report.scenarios.push_back(std::move(restore_result));

            const std::vector<test::scenarios::SeedFile> repair_files{
                {"repair-a.txt", std::string{demo_payload}},
                {"repair-b.txt", std::string{demo_payload}}};
            const auto repair_seed = test::scenarios::publish_seed_files(
                environment, "a", clients[0].second, repair_files);
            test::write_text(clients[3].second / "repair-a.txt", demo_payload);
            test::write_text(clients[3].second / "repair-b.txt", demo_payload);
            std::filesystem::create_directories(test_space /
                                                "repair-observation");
            auto repair_observation =
                application::observation::history::observe(
                    storage, *key, test_space / "repair-observation", false);
            const auto head_before =
                repair_observation && !repair_observation->logical_heads.empty()
                    ? repair_observation->logical_heads.front()
                    : std::string{};
            const auto repair_object = content_id(*key, demo_payload);
            const bool repair_removed =
                transport::remove(storage, repair_object).has_value();
            record_direct(report, "remove");
            const auto repair_sync =
                execute(environment, "repair", application::Operation::Sync);
            std::filesystem::create_directories(test_space /
                                                "repair-observation-after");
            auto repair_after = application::observation::history::observe(
                storage, *key, test_space / "repair-observation-after", false);
            const auto repaired_presence =
                transport::presence(storage, repair_object);
            const bool repair_ok =
                repair_seed && repair_removed && repair_sync &&
                std::holds_alternative<application::SyncCompleted>(
                    repair_sync->data) &&
                !std::get<application::SyncCompleted>(repair_sync->data)
                     .partial &&
                !std::get<application::SyncCompleted>(repair_sync->data)
                     .published &&
                repair_after && !repair_after->logical_heads.empty() &&
                repair_after->logical_heads.front() == head_before &&
                repaired_presence &&
                *repaired_presence == transport::Presence::Present &&
                kasumi::find_row(repair_after->effective_tree,
                                 "repair-a.txt") != nullptr &&
                kasumi::find_row(repair_after->effective_tree,
                                 "repair-b.txt") != nullptr;
            Scenario repair_result{.name = "local-source-repair",
                                   .status = repair_ok ? ScenarioStatus::Pass
                                                       : ScenarioStatus::Fail};
            if (!repair_ok) {
                std::string detail =
                    "verified local source repair did not pass";
                if (!repair_seed)
                    detail += "; seed=" + repair_seed.error();
                if (!repair_removed)
                    detail += "; object removal failed";
                if (!repair_sync)
                    detail += "; sync=" + repair_sync.error().detail;
                else if (const auto* summary =
                             std::get_if<application::SyncCompleted>(
                                 &repair_sync->data)) {
                    detail +=
                        "; partial=" + std::to_string(summary->partial) +
                        ", published=" + std::to_string(summary->published) +
                        ", pending=" + std::to_string(summary->pending);
                }
                if (!repair_after)
                    detail += "; observation=" + repair_after.error().detail;
                else if (!repair_after->logical_heads.empty() &&
                         repair_after->logical_heads.front() != head_before)
                    detail += "; logical head changed";
                if (!repaired_presence ||
                    *repaired_presence != transport::Presence::Present)
                    detail += "; object remains absent";
                repair_result.diagnostics.push_back(std::move(detail));
            }
            record_trace(repair_result);
            report.scenarios.push_back(std::move(repair_result));

            const auto fsck_healthy =
                execute(environment, "a", application::Operation::Fsck);
            const bool healthy_ok =
                fsck_healthy &&
                std::holds_alternative<application::FsckCompleted>(
                    fsck_healthy->data);
            Scenario healthy_result{.name = "fsck-healthy",
                                    .status = healthy_ok
                                                  ? ScenarioStatus::Pass
                                                  : ScenarioStatus::Fail};
            if (!healthy_ok && !fsck_healthy)
                healthy_result.diagnostics.push_back(
                    fsck_healthy.error().detail);
            record_trace(healthy_result);
            report.scenarios.push_back(std::move(healthy_result));

            auto current_state = load_state(app_data, "a");
            const auto* b_row =
                current_state && current_state->has_value()
                    ? kasumi::find_row((*current_state)->tree, "b.txt")
                    : nullptr;
            const auto fsck_object =
                b_row ? crypto::content_identifier(*key, b_row->hash)
                      : std::string{};
            const bool fsck_removed =
                !fsck_object.empty() &&
                transport::remove(storage, fsck_object).has_value();
            record_direct(report, "remove");
            const auto fsck_missing =
                execute(environment, "a", application::Operation::Fsck);
            const bool missing_ok = fsck_removed && !fsck_missing &&
                                    fsck_missing.error().code ==
                                        application::ErrorCode::FsckFailure;
            Scenario missing_result{.name = "fsck-missing",
                                    .status = missing_ok
                                                  ? ScenarioStatus::Pass
                                                  : ScenarioStatus::Fail};
            if (!missing_ok && !fsck_missing)
                missing_result.diagnostics.push_back(
                    fsck_missing.error().detail);
            record_trace(missing_result);
            report.scenarios.push_back(std::move(missing_result));

            const auto fsck_put =
                transport::put(storage, saved_ciphertext, fsck_object);
            record_direct(report, "put");
            const auto corrupt_file = test_space / "corrupt-b.ciphertext";
            auto ciphertext = read_bytes(saved_ciphertext);
            bool corrupted = false;
            if (fsck_put && ciphertext && !ciphertext->empty()) {
                ciphertext->back() ^= 1U;
                corrupted = write_bytes(corrupt_file, *ciphertext) &&
                            transport::put(storage, corrupt_file, fsck_object)
                                .has_value();
                record_direct(report, "put");
            }
            const auto fsck_corrupt =
                execute(environment, "a", application::Operation::Fsck);
            const bool corrupt_ok = corrupted && !fsck_corrupt &&
                                    fsck_corrupt.error().code ==
                                        application::ErrorCode::FsckFailure;
            Scenario corrupt_result{.name = "fsck-corrupt",
                                    .status = corrupt_ok
                                                  ? ScenarioStatus::Pass
                                                  : ScenarioStatus::Fail};
            if (!corrupt_ok && !fsck_corrupt)
                corrupt_result.diagnostics.push_back(
                    fsck_corrupt.error().detail);
            record_trace(corrupt_result);
            report.scenarios.push_back(std::move(corrupt_result));
        }
        report.scenarios.push_back(
            Scenario{.name = "gc-lifecycle",
                     .status = ScenarioStatus::NotRun,
                     .diagnostics = {
                         "existing GC live runner is coupled to remote "
                         "namespace preflight; Local adaptation is deferred"}});
    } catch (const std::exception& error) {
        report.diagnostics.push_back(error.what());
    }
    platform::perf_trace::force_enable(false);
    report.status = derive_status(report);
    return report;
}

nlohmann::json to_json(const Report& report) {
    auto result = nlohmann::json{
        {"schema_version", report.schema_version},
        {"provider_id", report.provider_id},
        {"transport", report.transport},
        {"platform", report.platform},
        {"status", report.status},
        {"cleanup", report.cleanup},
        {"target_root", report.target_root.string()},
        {"harness_requests", report.harness_requests},
        {"diagnostics", report.diagnostics},
        {"request_metrics_scope",
         "Kasumi perf_trace counters available for the selected operations; "
         "the Local transport does not expose generic GET/PUT call counters. "
         "Harness direct operations are counted separately."},
        {"capabilities", nlohmann::json::array()},
        {"scenarios", nlohmann::json::array()}};
    for (const auto& item : report.capabilities) {
        result["capabilities"].push_back(
            {{"name", item.name},
             {"status", name(item.status)},
             {"error",
              item.error
                  ? nlohmann::json{transport::error_code_name(*item.error)}
                  : nlohmann::json{}},
             {"detail", item.detail}});
    }
    for (const auto& item : report.scenarios) {
        result["scenarios"].push_back({{"name", item.name},
                                       {"status", name(item.status)},
                                       {"requests", item.requests},
                                       {"diagnostics", item.diagnostics}});
    }
    return result;
}

} // namespace kasumi::operational::provider_certification
