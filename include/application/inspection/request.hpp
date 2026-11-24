#ifndef KASUMI_APPLICATION_INSPECTION_REQUEST_HPP
#define KASUMI_APPLICATION_INSPECTION_REQUEST_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"
#include "application/execute.hpp"

#include <optional>
#include <stop_token>
#include <string>

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
};

struct InspectionInput {
    InspectionRequest request;
    Credentials credentials;
    ExecutionEnvironment environment;
    ProgressCallback on_progress{};
    std::stop_token stop_token{};
};

} // namespace kasumi::application

#endif
