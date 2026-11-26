#include "application/daemon/ipc_security.hpp"
#include "application/daemon/web_http.hpp"
#include "application/daemon/web_icons.hpp"
#include "application/daemon/web_profile_json.hpp"
#include "application/daemon/web_routes.hpp"
#include "core/node.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "runtime/paths.hpp"

#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::daemon_detail {
namespace {

Profile find_profile(const ExecutionEnvironment& env, const std::string& name) {
    auto profiles = require(list_profiles(env));
    const auto it = std::ranges::find(profiles, name, &Profile::name);
    if (it == profiles.end())
        throw HttpError{404, "profile not found"};
    return *it;
}

KeyStorage storage_value(const Json& body) {
    const auto& name = body.at("key_storage").get_ref<const std::string&>();
    for (auto mode :
         {KeyStorage::Vault, KeyStorage::File, KeyStorage::Memory}) {
        if (name == to_string(mode))
            return mode;
    }
    throw HttpError{400, "unknown key storage mode"};
}

void apply_settings(Profile& p, const Json& body, bool create = false) {
    for (const auto& [key, value] : body.items()) {
        if (key == "local_dir")
            p.local_dir = platform::path::from_utf8(value.get<std::string>());
        else if (key == "remote_dir")
            value.get_to(p.remote_dir);
        else if (key == "watch_enabled")
            p.watch_enabled = value.is_null()
                                  ? std::nullopt
                                  : std::optional(value.get<bool>());
        else if (key == "paused")
            value.get_to(p.paused);
        else if (key == "icon") {
            p.icon = value.is_null() ? std::string{} : value.get<std::string>();
            if (!runtime::is_valid_profile_icon(p.icon))
                throw HttpError{400, "invalid profile icon"};
        } else if (key == "bandwidth_limit")
            p.bandwidth_limit = value.is_null()
                                    ? std::nullopt
                                    : std::optional(value.get<std::string>());
        else if (key == "rclone_config")
            p.rclone_config = value.is_null()
                                  ? std::nullopt
                                  : std::optional(platform::path::from_utf8(
                                        value.get<std::string>()));
        else if (key == "transfer_concurrency" ||
                 key == "sync_interval_seconds" || key == "min_history_depth" ||
                 key == "min_history_age_hours") {
            if (!value.is_null() && (!value.is_number_unsigned() ||
                                     value.get<std::uint64_t>() > UINT32_MAX))
                throw HttpError{400, "expected a non-negative 32-bit integer"};
            if (key == "transfer_concurrency")
                p.transfer_concurrency =
                    value.is_null() ? std::nullopt
                                    : std::optional(value.get<std::uint32_t>());
            if (key == "sync_interval_seconds")
                p.sync_interval_seconds =
                    value.is_null() ? std::nullopt
                                    : std::optional(value.get<std::uint32_t>());
            if (key == "min_history_depth")
                value.get_to(p.min_history_depth);
            if (key == "min_history_age_hours")
                value.get_to(p.min_history_age_hours);
        } else if (key != "allow_empty_local" &&
                   !(create && (key == "name" || key == "key_storage" ||
                                key == "master_key" || key == "salt_password" ||
                                key == "password" || key == "verify"))) {
            throw HttpError{400, "unknown profile setting"};
        }
    }
}

Json profile_info(const WebContext& ctx,
                  const Profile& p,
                  const DaemonStatusReport& daemon) {
    Json data = p;
    auto summary = inspect_profile_local_summary(ctx.environment, p.name);
    data["state"] = summary.state;
    data["problem"] = summary.problem;
    data["activity"] = std::move(summary.activity);
    auto live =
        std::ranges::find(daemon.profiles, p.name, &DaemonProfileStatus::name);
    data["daemon"] =
        live == daemon.profiles.end() ? Json(nullptr) : Json(*live);
    return data;
}

Json preview_file(const std::filesystem::path& root, const std::string& path) {
    using namespace platform::private_storage;
    if (!valid_logical_path(path))
        throw HttpError{400, "invalid conflict path"};
    const auto relative = platform::path::from_utf8(path);
    if (relative.has_root_path())
        throw HttpError{400, "invalid conflict path"};
    auto normalized_root = root.lexically_normal();
    if (!normalized_root.has_filename() && normalized_root.has_relative_path())
        normalized_root = normalized_root.parent_path();
    const auto file = (normalized_root / relative).lexically_normal();
    if (file.lexically_relative(normalized_root) != relative)
        throw HttpError{409, "unsafe conflict path"};
    for (auto parent = file.parent_path();; parent = parent.parent_path()) {
        if (is_reparse_or_symlink(parent))
            throw HttpError{409, "unsafe conflict path"};
        if (parent == normalized_root)
            break;
        if (parent == parent.root_path() || parent.empty())
            throw HttpError{409, "unsafe conflict path"};
    }
    auto input = open_regular_file(file);
    if (!input)
        throw HttpError{409, "conflict file changed"};
    constexpr std::size_t limit = 1024 * 1024;
    std::vector<std::uint8_t> bytes(
        static_cast<std::size_t>(std::min<std::uint64_t>(limit, input->size)));
    if (!read_regular_file_exact(*input, bytes))
        throw HttpError{409, "cannot read conflict file"};
    // Hex preserves arbitrary image data and invalid UTF-8 in text previews.
    return {{"path", path},
            {"size", input->size},
            {"truncated", bytes.size() != input->size},
            {"hex", encode_hex(bytes)}};
}
} // namespace

void register_profile_routes(httplib::Server& server, const WebContext& ctx) {
    register_icon_routes(server, ctx);
    server.Get("/v1/profiles", json_route([ctx](const auto&) {
                   Json rows = Json::array();
                   auto daemon = ctx.status();
                   for (const auto& profile :
                        require(list_profiles(ctx.environment)))
                       rows.push_back(profile_info(ctx, profile, daemon));
                   return Json{{"profiles", std::move(rows)}};
               }));
    server.Get("/v1/profiles/([^/]+)", json_route([ctx](const auto& req) {
                   return profile_info(
                       ctx,
                       find_profile(ctx.environment, req.matches[1].str()),
                       ctx.status());
               }));
    server.Post("/v1/profiles", json_route([ctx](const auto& req) {
                    auto body = parse_body(req);
                    Profile p;
                    p.name = body->at("name").template get<std::string>();
                    if (body->contains("key_storage"))
                        p.key_storage = storage_value(*body);
                    if (p.key_storage == KeyStorage::Vault)
                        require(check_os_vault_available());
                    apply_settings(p, *body, true);
                    auto cred = credential_input(*body);
                    const bool verify = body->value("verify", false);
                    require(create_profile(
                        ctx.environment, p, std::move(cred), verify, ctx.stop));
                    ctx.reload();
                    return Json(p);
                }));
    server.Patch("/v1/profiles/([^/]+)", json_route([ctx](const auto& req) {
                     const auto name = req.matches[1].str();
                     const auto original = find_profile(ctx.environment, name);
                     auto p = original;
                     auto body = parse_body(req);
                     apply_settings(p, *body);
                     {
                         InternalProfileLockGuard lock_guard(
                             ctx.track_internal_lock, name);
                         require(update_profile(
                             ctx.environment,
                             p,
                             body->value("allow_empty_local", false),
                             &original));
                     }
                     if (original.icon.starts_with("custom:") &&
                         !p.icon.starts_with("custom:")) {
                         if (const auto paths = runtime::resolve_profile_paths(
                                 ctx.environment.app_data_dir, name)) {
                             remove_custom_icon_files(paths->profile_dir);
                         }
                     }
                     ctx.reload();
                     return Json(p);
                 }));
    server.Delete(
        "/v1/profiles/([^/]+)", json_route([ctx](const auto& req) {
            if (!parse_body(req)->value("confirm", false))
                throw HttpError{400, "explicit confirmation required"};
            const auto name = req.matches[1].str();
            InternalProfileLockGuard lock_guard(ctx.track_internal_lock, name);
            require(delete_profile(ctx.environment, name));
            ctx.reload();
            return Json{{"deleted", true}};
        }));
    server.Post(
        "/v1/profiles/([^/]+)/(clone|rename|storage|key|test)",
        json_route([ctx](const auto& req) -> Json {
            const auto name = req.matches[1].str();
            const auto action = req.matches[2].str();
            auto body = parse_body(req);
            if (action == "test")
                return require(test_profile_connection(
                    ctx.environment, name, ctx.credentials(name), ctx.stop));
            {
                InternalProfileLockGuard lock_guard(ctx.track_internal_lock,
                                                    name);
                if (action == "clone")
                    require(clone_profile(
                        ctx.environment,
                        name,
                        body->at("name").template get<std::string>()));
                if (action == "rename")
                    require(rename_profile(
                        ctx.environment,
                        name,
                        body->at("name").template get<std::string>()));
                if (action == "storage") {
                    auto p = find_profile(ctx.environment, name);
                    auto original = p;
                    p.key_storage = storage_value(*body);
                    if (p.key_storage == KeyStorage::Vault)
                        require(check_os_vault_available());
                    require(
                        update_profile(ctx.environment, p, false, &original));
                }
                if (action == "key") {
                    auto p = find_profile(ctx.environment, name);
                    if (p.key_storage == KeyStorage::Vault)
                        require(check_os_vault_available());
                    require(set_profile_key(ctx.environment,
                                            name,
                                            credential_input(*body),
                                            body->value("replace", false)));
                }
            }
            ctx.reload();
            return {{"ok", true}};
        }));
    server.Get("/v1/rclone/remotes", json_route([](const auto&) {
                   return discover_rclone_remotes();
               }));
    server.Get("/v1/diagnostics(?:/([^/]+))?",
               json_route([ctx](const auto& req) {
                   const auto live = ctx.status();
                   return require(collect_diagnostics(
                       ctx.environment, req.matches[1].str(), &live));
               }));
    server.Post(
        "/v1/profiles/([^/]+)/ignore/check", json_route([ctx](const auto& req) {
            auto body = parse_body(req);
            return require(check_profile_ignore(
                ctx.environment,
                req.matches[1].str(),
                body->at("paths").template get<std::vector<std::string>>()));
        }));
    server.Post(
        "/v1/profiles/([^/]+)/ignore/init", json_route([ctx](const auto& req) {
            auto body = parse_body(req);
            auto name = body->value("preset", std::string("default"));
            for (auto preset : {IgnorePreset::Default,
                                IgnorePreset::Dev,
                                IgnorePreset::Office,
                                IgnorePreset::Minimal}) {
                if (name == to_string(preset)) {
                    auto profile = req.matches[1].str();
                    InternalProfileLockGuard lock_guard(
                        ctx.track_internal_lock, profile);
                    return with_profile_lock(ctx.environment, profile, [&] {
                        return require(
                            init_profile_ignore(ctx.environment,
                                                profile,
                                                preset,
                                                body->value("force", false),
                                                body->value("dry_run", false)));
                    });
                }
            }
            throw HttpError{400, "unknown ignore preset"};
        }));
    server.Get("/v1/conflicts/([^/]+)", json_route([ctx](const auto& req) {
                   return require(list_local_conflicts(ctx.environment,
                                                       req.matches[1].str()));
               }));
    server.Get(
        "/v1/conflicts/([^/]+)/diff",
        json_route([ctx](const auto& req) -> Json {
            const auto path = req.get_param_value("path");
            const auto artifact_path = req.get_param_value("artifact");
            if (!valid_logical_path(path) || !valid_logical_path(artifact_path))
                throw HttpError{400, "invalid conflict path"};
            const auto profile = req.matches[1].str();
            InternalProfileLockGuard lock_guard(ctx.track_internal_lock,
                                                profile);
            return with_profile_lock(
                ctx.environment, profile, [&]() -> Json {
                    auto conflicts = require(list_local_conflicts(
                        ctx.environment, req.matches[1].str()));
                    const auto group =
                        std::ranges::find(conflicts.groups,
                                          path,
                                          &LocalConflictGroup::canonical_path);
                    if (group == conflicts.groups.end())
                        throw HttpError{404, "conflict group not found"};
                    const auto artifact =
                        std::ranges::find(group->artifacts,
                                          artifact_path,
                                          &LocalConflictArtifact::path);
                    if (artifact == group->artifacts.end())
                        throw HttpError{404, "artifact not found"};
                    return {
                        {"canonical",
                         group->canonical_exists
                             ? preview_file(conflicts.local_dir,
                                            group->canonical_path)
                             : Json(nullptr)},
                        {"artifact",
                         preview_file(conflicts.local_dir, artifact->path)}};
                });
        }));
    server.Post(
        "/v1/conflicts/([^/]+)/resolve", json_route([ctx](const auto& req) {
            auto body = parse_body(req);
            ResolveConflictRequest action;
            action.profile_name = req.matches[1].str();
            body->at("path").get_to(action.canonical_path);
            const auto choice = body->at("choice");
            if (choice == "keep_artifact")
                action.choice = ConflictResolutionChoice::KeepArtifact;
            else if (choice != "keep_canonical")
                throw HttpError{400, "unknown conflict resolution"};
            action.artifact_selector = body->value("artifact", std::string{});
            action.dry_run = body->value("dry_run", false);
            return require(resolve_local_conflict(ctx.environment, action));
        }));
}
} // namespace kasumi::application::daemon_detail
