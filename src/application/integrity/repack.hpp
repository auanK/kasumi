#ifndef KASUMI_APPLICATION_INTEGRITY_REPACK_HPP
#define KASUMI_APPLICATION_INTEGRITY_REPACK_HPP

#include "application/integrity/maintenance.hpp"
#include "application/integrity/repack_planner.hpp"
#include "crypto/file_crypto.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace kasumi::application {
class ProgressMeter;
}

namespace kasumi::application::integrity::repack {

// Execution options controlling Micro-Pack consolidation.
struct Options {
    Policy policy{};
    bool dry_run = false;
    // Zero selects application::content_concurrency().
    std::size_t max_parallelism = 0;
};

// Outcome and metrics of one repack execution or dry-run.
struct Result {
    Plan plan;
    bool dry_run = false;
    bool published = false;
    std::string published_commit_id;
    std::uint64_t published_height = 0;
    std::size_t pruned_markers = 0;
    std::uint64_t wire_upload_bytes = 0;
    std::uint64_t physical_objects_uploaded = 0;
    std::chrono::nanoseconds duration{};
};

// Consolidates fragmented Micro-Packs and loose small files from live local
// sources without downloading or deleting existing remote objects.
std::expected<Result, integrity::Error>
execute(const runtime::RuntimeData& runtime_data,
        transport::Transport& storage,
        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
        const Options& options = {},
        ProgressMeter* meter = nullptr);

} // namespace kasumi::application::integrity::repack

#endif
