#ifndef KASUMI_TEST_PROVIDER_SCENARIOS_HPP
#define KASUMI_TEST_PROVIDER_SCENARIOS_HPP

#include "application/environment.hpp"
#include "transport/transport.hpp"

#include <expected>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kasumi::test::scenarios {

using SeedFile = std::pair<std::string, std::string>;

struct TransportRoundTripObservation {
    bool passed = false;
    std::map<std::string, std::uint64_t> requests;
    std::vector<std::string> diagnostics;
};

struct SyncScenarioClient {
    std::string profile;
    std::filesystem::path local_root;
    application::ExecutionEnvironment environment;
};

struct TwoClientSyncScenario {
    std::string remote_locator;
    std::filesystem::path scratch_root;
    SyncScenarioClient a;
    SyncScenarioClient b;
};

TransportRoundTripObservation
transport_round_trip(transport::Transport& storage,
                     const std::filesystem::path& scratch_root);

std::expected<void, std::string>
sync(const application::ExecutionEnvironment& environment,
     std::string_view profile);

std::expected<void, std::string>
publish_seed_files(const application::ExecutionEnvironment& environment,
                   std::string_view profile,
                   const std::filesystem::path& local_root,
                   const std::vector<SeedFile>& files);

std::expected<void, std::string>
materialize_files(const application::ExecutionEnvironment& environment,
                  std::string_view profile,
                  const std::filesystem::path& local_root,
                  const std::vector<SeedFile>& files);

std::expected<bool, std::string>
no_op_sync(const application::ExecutionEnvironment& environment,
           std::string_view profile);

std::expected<void, std::string>
bidirectional_update(const TwoClientSyncScenario& scenario);
std::expected<void, std::string>
logical_delete(const TwoClientSyncScenario& scenario);
std::expected<void, std::string>
two_client_conflict(const TwoClientSyncScenario& scenario);

} // namespace kasumi::test::scenarios

#endif
