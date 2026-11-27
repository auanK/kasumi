#ifndef KASUMI_APPLICATION_INSPECTION_REQUEST_HPP
#define KASUMI_APPLICATION_INSPECTION_REQUEST_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"
#include "application/execute.hpp"

#include <optional>
#include <stop_token>
#include <string>

namespace kasumi::transport {
struct Transport;
}

namespace kasumi::application::history_storage {
struct CommitCache;
}

namespace kasumi::application {

// Read-only inspection query provided by Application.
enum class InspectionOperation {
    RemoteHeads,
    RemoteTree,
    RemoteCommits,
    RemoteSummary,
    RemoteStat,
    RemoteCommit,
    RemoteGet,
    RemoteEpochs,
    RemoteEpoch,
    RemoteContents,
    RemoteContentsAudit,
    RemoteContent,
    RemoteMarkers,
    RemoteObjects,
    RemoteOrphans,
    RemoteWriters,
    RemoteHealth,
    RemoteLog,
    RemoteRestore,
};

struct DownloadSlice {
    std::uint64_t offset;
    std::uint64_t length;
};

struct InspectionRequest {
    InspectionOperation operation = InspectionOperation::RemoteHeads;
    std::string profile_name;
    std::optional<std::string> head_commit_id;
    std::optional<std::string> logical_path;
    std::optional<std::string> commit_id;
    std::optional<std::string> destination_path;
    std::optional<std::string> epoch_selector;
    std::optional<std::string> content_id;
    bool dry_run = false;
    std::optional<std::string> bandwidth_limit = std::nullopt;
    std::optional<std::uint32_t> transfer_concurrency = std::nullopt;
    std::optional<DownloadSlice> download_slice = std::nullopt;
    bool include_space_usage = false;
    bool bypass_commit_cache = false;
};

struct InspectionInput {
    InspectionRequest request;
    Credentials credentials;
    ExecutionEnvironment environment;
    ProgressCallback on_progress{};
    std::stop_token stop_token{};
    // Optional transport owned exclusively by the caller for this profile.
    transport::Transport* transport_cache = nullptr;
    // Optional thread-safe commit cache shared across inspections.
    history_storage::CommitCache* commit_cache = nullptr;
    // When true, historical tree/pair inspections may be served directly from
    // an already authenticated commit in commit_cache.
    bool allow_cached_commit = false;
};

} // namespace kasumi::application

#endif
