#pragma once

#include "application/credentials.hpp"
#include "application/profile.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/profile.hpp"
#include "runtime/vault.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <string>
#include <string_view>

namespace kasumi::application::daemon_detail {
using Json = nlohmann::json;

struct InternalProfileLockGuard {
    std::function<void(std::string_view, bool)> tracker;
    std::string profile_name;

    InternalProfileLockGuard(
        std::function<void(std::string_view, bool)> tracker_fn,
        std::string_view name)
        : tracker(std::move(tracker_fn)), profile_name(name) {
        if (tracker && !profile_name.empty())
            tracker(profile_name, true);
    }

    ~InternalProfileLockGuard() noexcept {
        if (tracker && !profile_name.empty()) {
            try {
                tracker(profile_name, false);
            } catch (...) {
            }
        }
    }

    InternalProfileLockGuard(const InternalProfileLockGuard&) = delete;
    InternalProfileLockGuard&
    operator=(const InternalProfileLockGuard&) = delete;
};

struct HttpError {
    int status;
    std::string message;
    std::string code{};
    std::string active_operation{};
};

inline void scrub_json(Json* value) noexcept {
    if (value->is_string()) {
        auto& s = value->get_ref<std::string&>();
        crypto::secure_memory::wipe(s.data(), s.size());
    } else if (value->is_structured()) {
        for (auto& child : *value)
            scrub_json(&child);
    }
}

// Keep the parsed body owned by the handler until all credentials have been
// consumed.
inline auto parse_body(const httplib::Request& req,
                       std::size_t max_bytes = 65536U) {
    if (req.body.size() > max_bytes)
        throw HttpError{413, "payload too large"};
    auto destroy = +[](Json* doc) {
        scrub_json(doc);
        delete doc;
    };
    std::unique_ptr<Json, decltype(destroy)> body(new Json, destroy);
    if (req.body.empty())
        *body = Json::object();
    else
        *body = Json::parse(req.body, nullptr, false);
    if (!body->is_object())
        throw HttpError{400, "expected a JSON object"};
    return body;
}

inline ProfileCredentials credential_input(const Json& body) {
    if (body.contains("master_key")) {
        auto key = runtime::vault::decode_hex(
            body.at("master_key").get_ref<const std::string&>());
        if (!key)
            throw HttpError{400, "invalid master key"};
        crypto::secure_memory::WipeGuard wipe(*key);
        return MasterKeyBytes{*key};
    }
    auto key = runtime::vault::derive(
        body.at("password").get_ref<const std::string&>(),
        body.at("salt_password").get_ref<const std::string&>());
    if (!key)
        throw HttpError{400, "invalid profile credentials"};
    crypto::secure_memory::WipeGuard wipe(*key);
    return MasterKeyBytes{*key};
}

// Validate before composing the lock path, and keep the same handle until the
// operation returns.
inline auto with_profile_lock(const ExecutionEnvironment& environment,
                              const std::string& name,
                              auto&& operation) {
    if (!runtime::is_valid_profile_name(name))
        throw HttpError{400, "invalid profile name"};
    auto handle = platform::acquire_profile_lock(environment.app_data_dir /
                                                 ("profile-" + name + ".lock"));
    if (!handle)
        throw HttpError{409, "profile busy", "lock_busy", "external"};
    auto release = +[](std::intptr_t* h) {
        platform::release_profile_lock(*h);
    };
    std::unique_ptr<std::intptr_t, decltype(release)> held(&*handle, release);
    return operation();
}

inline HttpError http_error(const ProfileError& error) {
    using E = ProfileErrorCode;
    switch (error.code) {
        case E::LockFailure:
            return {409, error.detail, "lock_busy", "external"};
        case E::AlreadyExists:
            return {409, error.detail};
        case E::NotFound:
            return {404, error.detail};
        case E::CredentialFailure:
            return {403, error.detail};
        default:
            return {400, error.detail};
    }
}

template <typename T> T require(std::expected<T, ProfileError> value) {
    if (!value)
        throw http_error(value.error());
    if constexpr (!std::is_void_v<T>)
        return std::move(*value);
}

template <typename Fn> httplib::Server::Handler json_route(Fn fn) {
    return [fn = std::move(fn)](const httplib::Request& req,
                                httplib::Response& res) {
        Json result = fn(req);
        res.set_content(
            result.dump(-1, ' ', false, Json::error_handler_t::replace),
            "application/json");
    };
}
} // namespace kasumi::application::daemon_detail
