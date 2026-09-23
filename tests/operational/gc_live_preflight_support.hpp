#ifndef KASUMI_GC_LIVE_PREFLIGHT_SUPPORT_HPP
#define KASUMI_GC_LIVE_PREFLIGHT_SUPPORT_HPP

#include "remote_copy_smoke_support.hpp"

#include <chrono>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::operational::gc_live_preflight {

enum class ChildDisposition { Unused, Existing, Refused };
enum class PostInitializeDisposition { Empty, Refused };

struct ListingObservation {
    std::string result = "FAILED";
    std::size_t entry_count = 0;
    std::optional<transport::ErrorCode> error_category;
    std::optional<int> native_code;
    std::string error_message;
};

struct RcDiagnostic {
    std::string endpoint = "operations/list";
    std::string request_fs;
    std::string request_remote;
    std::string result = "FAILED";
    std::optional<std::size_t> entry_count;
    std::optional<int> native_status;
    std::optional<transport::ErrorCode> error_category;
    std::string error_message;
};

struct PreInitializeObservation {
    ListingObservation transport;
    RcDiagnostic raw_rc;
};

struct PostInitializeObservation {
    ListingObservation transport;
};

struct Classification {
    ChildDisposition disposition = ChildDisposition::Refused;
    std::string reason;
};

struct CleanupResult {
    std::string result;
    std::string detail;
    std::size_t removed_objects = 0;
    std::optional<transport::ErrorCode> error_category;
};

struct ChildStorage {
    remote_copy_smoke::RemoteParent parent;
    std::string child;
    transport::Transport storage;
};

std::expected<std::string, std::string>
child_namespace(std::string_view random_hex);
bool valid_child(std::string_view child) noexcept;
std::expected<std::string, std::string> child_location(
    const remote_copy_smoke::RemoteParent& parent,
    std::string_view child);

PreInitializeObservation observe_pre_initialize(
    transport::Transport& parent_storage,
    const remote_copy_smoke::RemoteParent& parent,
    std::string_view child,
    std::chrono::milliseconds diagnostic_deadline = std::chrono::minutes{2});
Classification classify_pre_initialize(
    const PreInitializeObservation& observation,
    const remote_copy_smoke::RemoteParent& parent,
    std::string_view child);

std::expected<ChildStorage, transport::Error> open_child_storage(
    const remote_copy_smoke::RemoteParent& parent,
    std::string_view child);
transport::Result initialize_child(
    ChildStorage& child,
    const PreInitializeObservation& pre_initialize);
PostInitializeObservation observe_post_initialize(ChildStorage& child);
PostInitializeDisposition classify_post_initialize(
    const PostInitializeObservation& observation) noexcept;
transport::Result establish_ownership_marker(
    ChildStorage& child,
    const PostInitializeObservation& post_initialize,
    std::string_view owner_token,
    const std::filesystem::path& marker_source,
    const std::filesystem::path& marker_readback);
CleanupResult cleanup_owned_child(
    ChildStorage& child,
    std::string_view owner_token,
    const std::vector<std::string>& object_identifiers,
    const std::filesystem::path& local_scratch);

std::string sanitize_rc_message(std::string message,
                                std::string_view username,
                                std::string_view password);
nlohmann::json to_json(const PreInitializeObservation& observation,
                       const Classification& classification);
nlohmann::json to_json(const PostInitializeObservation& observation,
                       PostInitializeDisposition classification);
nlohmann::json to_json(const CleanupResult& cleanup);

} // namespace kasumi::operational::gc_live_preflight

#endif
