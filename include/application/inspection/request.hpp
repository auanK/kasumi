#ifndef KASUMI_APPLICATION_INSPECTION_REQUEST_HPP
#define KASUMI_APPLICATION_INSPECTION_REQUEST_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"

#include <optional>
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
    RemoteQuarantine,
    RemoteWriters,
    RemoteHealth,
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
};

struct InspectionInput {
    InspectionRequest request;
    Credentials credentials;
    ExecutionEnvironment environment;
};

} // namespace kasumi::application

#endif
