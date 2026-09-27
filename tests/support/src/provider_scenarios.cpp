#include "kasumi/test/provider_scenarios.hpp"

#include "application/execute.hpp"
#include "application/request.hpp"
#include "kasumi/test/filesystem.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <filesystem>

namespace kasumi::test::scenarios {
namespace {

std::expected<void, std::string>
ensure_directory(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::create_directories(path, error);
    if (error) {
        return std::unexpected(error.message());
    }
    return {};
}

} // namespace

std::expected<void, std::string>
sync(const application::ExecutionEnvironment& environment,
     std::string_view profile) {
    auto result = application::execute(
        {application::Request{application::Operation::Sync,
                              std::string{profile}},
         application::Credentials{application::NoCredentials{}},
         environment});
    if (!result) {
        return std::unexpected(result.error().detail);
    }
    return {};
}

std::expected<void, std::string>
publish_seed_files(const application::ExecutionEnvironment& environment,
                   std::string_view profile,
                   const std::filesystem::path& local_root,
                   const std::vector<SeedFile>& files) {
    if (auto created = ensure_directory(local_root); !created) {
        return created;
    }
    for (const auto& [relative, contents] : files) {
        const auto target = local_root / platform::path::from_utf8(relative);
        if (auto created = ensure_directory(target.parent_path()); !created) {
            return created;
        }
        write_text(target, contents);
    }
    return sync(environment, profile);
}

std::expected<void, std::string>
materialize_files(const application::ExecutionEnvironment& environment,
                  std::string_view profile,
                  const std::filesystem::path& local_root,
                  const std::vector<SeedFile>& files) {
    auto synchronized = sync(environment, profile);
    if (!synchronized) {
        return synchronized;
    }
    for (const auto& [relative, contents] : files) {
        const auto target = local_root / platform::path::from_utf8(relative);
        std::error_code error;
        if (!std::filesystem::is_regular_file(target, error) || error) {
            return std::unexpected("materialized file is missing: " + relative);
        }
        if (read_text(target) != contents) {
            return std::unexpected("materialized bytes differ: " + relative);
        }
    }
    return {};
}

std::expected<bool, std::string>
no_op_sync(const application::ExecutionEnvironment& environment,
           std::string_view profile) {
    auto result = application::execute(
        {application::Request{application::Operation::Sync,
                              std::string{profile}},
         application::Credentials{application::NoCredentials{}},
         environment});
    if (!result) {
        return std::unexpected(result.error().detail);
    }
    const auto* summary =
        std::get_if<application::SyncCompleted>(&result->data);
    if (summary == nullptr) {
        return std::unexpected("sync did not return SyncCompleted");
    }
    return result->operation == application::Operation::Sync &&
           !summary->published && !summary->partial &&
           summary->pending_paths.empty();
}

} // namespace kasumi::test::scenarios
