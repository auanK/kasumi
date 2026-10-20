#include "application/use_cases/context.hpp"
#include "core/hasher.hpp"
#include "crypto/content.hpp"
#include "crypto/key_derivation.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kasumi::application::detail {
std::expected<Response, Error> run_sync(OperationContext& context);
}

namespace {

using Clock = std::chrono::steady_clock;

std::uint64_t elapsed_us(Clock::time_point started) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() -
                                                              started)
            .count());
}

struct Counts {
    kasumi::transport::Transport* base = nullptr;
    std::size_t content_puts = 0;
    std::size_t puts = 0;
    std::size_t gets = 0;
    std::size_t presences = 0;
    std::size_t lists = 0;
    std::size_t physical_hashes = 0;
    std::size_t control_batches = 0;
    std::size_t control_batch_ids = 0;
};

void destroy_counts(void*) noexcept {
}

kasumi::transport::Result counting_initialize(void* context) {
    auto* state = static_cast<Counts*>(context);
    return kasumi::transport::initialize(*state->base);
}

kasumi::transport::Result counting_put(void* context,
                                       const std::filesystem::path& source,
                                       std::string_view identifier) {
    auto* state = static_cast<Counts*>(context);
    ++state->puts;
    if (identifier.find('/') == std::string_view::npos) {
        ++state->content_puts;
    }
    return kasumi::transport::put(*state->base, source, identifier);
}

kasumi::transport::Result
counting_get(void* context,
             std::string_view identifier,
             const std::filesystem::path& destination) {
    auto* state = static_cast<Counts*>(context);
    ++state->gets;
    return kasumi::transport::get(*state->base, identifier, destination);
}

kasumi::transport::PresenceResult
counting_presence(void* context, std::string_view identifier) {
    auto* state = static_cast<Counts*>(context);
    ++state->presences;
    return kasumi::transport::presence(*state->base, identifier);
}

kasumi::transport::ListingResult counting_list(void* context) {
    auto* state = static_cast<Counts*>(context);
    ++state->lists;
    return kasumi::transport::list(*state->base);
}

kasumi::transport::ListingResult counting_list_prefix(void* context,
                                                      std::string_view prefix) {
    auto* state = static_cast<Counts*>(context);
    ++state->lists;
    return kasumi::transport::list(*state->base, prefix);
}

std::expected<std::string, kasumi::transport::Error> counting_physical_hash(
    void* context, std::string_view identifier, std::string_view algorithm) {
    auto* state = static_cast<Counts*>(context);
    ++state->physical_hashes;
    return kasumi::transport::physical_hash(
        *state->base, identifier, algorithm);
}

kasumi::transport::ControlReadBatchResponse counting_control_read_batch(
    void* context, const kasumi::transport::ControlReadBatchRequest& request) {
    auto* state = static_cast<Counts*>(context);
    ++state->control_batches;
    state->control_batch_ids += request.presence_identifiers.size();

    kasumi::transport::ControlReadBatchResult result;
    for (const auto& prefix : request.list_prefixes) {
        auto listing = kasumi::transport::list(*state->base, prefix);
        if (!listing) {
            return std::unexpected(listing.error());
        }
        ++state->lists;
        result.listings.push_back(std::move(*listing));
    }
    result.presences.reserve(request.presence_identifiers.size());
    for (const auto& identifier : request.presence_identifiers) {
        auto presence = kasumi::transport::presence(*state->base, identifier);
        if (!presence) {
            return std::unexpected(presence.error());
        }
        ++state->presences;
        result.presences.push_back(*presence);
    }
    return result;
}

kasumi::transport::RemovalResult counting_remove(void* context,
                                                 std::string_view identifier) {
    auto* state = static_cast<Counts*>(context);
    return kasumi::transport::remove(*state->base, identifier);
}

kasumi::transport::Transport make_counting_storage(Counts& counts) {
    return kasumi::transport::Transport{
        .state =
            kasumi::transport::TransportStateHandle{&counts, destroy_counts},
        .storage =
            kasumi::transport::StorageOperations{
                .initialize = counting_initialize,
                .put = counting_put,
                .get = counting_get,
                .presence = counting_presence,
                .list = counting_list,
                .list_prefix = counting_list_prefix,
                .physical_hash = counting_physical_hash,
                .control_read_batch = counting_control_read_batch,
                .remove = counting_remove,
            },
    };
}

std::string content_bytes(std::size_t index, std::size_t unique_contents) {
    return "gc-r3-content-" + std::to_string(index % unique_contents) +
           std::string(240, 'x');
}

bool write_files(const std::filesystem::path& local,
                 std::size_t files,
                 std::size_t unique_contents) {
    std::error_code error;
    std::filesystem::create_directories(local, error);
    if (error) {
        return false;
    }
    for (std::size_t index = 0; index < files; ++index) {
        std::ofstream output(local / ("file-" + std::to_string(index) + ".bin"),
                             std::ios::binary | std::ios::trunc);
        if (!output) {
            return false;
        }
        output << content_bytes(index, unique_contents);
    }
    return true;
}

struct Fixture {
    std::filesystem::path root;
    std::filesystem::path local;
    std::filesystem::path profile;
    std::filesystem::path database;
    std::filesystem::path storage_root;
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    Counts counts;
    kasumi::transport::Transport base;
    kasumi::runtime::RuntimeData runtime;
    kasumi::application::detail::OperationContext context;
    std::size_t files = 0;
    std::size_t content_ids = 0;

    [[nodiscard]] std::filesystem::path
    content_path(std::size_t content_index) const {
        const auto hash = kasumi::hasher::hash_string(
            content_bytes(content_index, content_ids));
        return storage_root /
               kasumi::platform::path::from_utf8(
                   kasumi::crypto::content_identifier(key, hash));
    }
};

bool create_fixture(const std::filesystem::path& root,
                    std::size_t files,
                    std::size_t content_ids,
                    Fixture& fixture) {
    if (files == 0 || content_ids == 0 || content_ids > files) {
        return false;
    }
    fixture.root = root;
    fixture.files = files;
    fixture.content_ids = content_ids;
    fixture.local = root / "local";
    fixture.profile = root / "profile";
    fixture.database = fixture.profile / "state.db";
    fixture.storage_root = root / "storage";

    std::error_code error;
    std::filesystem::create_directories(fixture.profile, error);
    if (error || !write_files(fixture.local, files, content_ids)) {
        return false;
    }
    auto opened =
        kasumi::transport::open_transport(fixture.storage_root.string());
    if (!opened || !kasumi::transport::initialize(*opened)) {
        return false;
    }
    fixture.base = std::move(*opened);
    fixture.counts.base = &fixture.base;
    auto storage = make_counting_storage(fixture.counts);
    if (!kasumi::state_storage::initialize(fixture.database)) {
        return false;
    }
    fixture.runtime = kasumi::runtime::RuntimeData{
        .local_dir = fixture.local,
        .database_path = fixture.database,
        .key_path = fixture.profile / "key.bin",
        .storage_location = fixture.storage_root.string(),
    };
    fixture.context.operation = kasumi::application::Operation::Sync;
    fixture.context.runtime = fixture.runtime;
    fixture.context.summary = {
        .local_dir = fixture.local,
        .remote_dir = kasumi::platform::path::to_utf8(fixture.storage_root),
    };
    fixture.context.key = fixture.key;
    fixture.context.storage = std::move(storage);
    return true;
}

void reset_counts(Counts& counts) {
    counts.content_puts = 0;
    counts.puts = 0;
    counts.gets = 0;
    counts.presences = 0;
    counts.lists = 0;
    counts.physical_hashes = 0;
    counts.control_batches = 0;
    counts.control_batch_ids = 0;
}

bool run_phase(Fixture& fixture,
               std::string_view phase,
               bool repair,
               std::size_t repair_content_index) {
    reset_counts(fixture.counts);
    kasumi::platform::perf_trace::reset();
    if (repair) {
        std::error_code remove_error;
        const auto removed = std::filesystem::remove(
            fixture.content_path(repair_content_index), remove_error);
        if (!removed || remove_error) {
            std::cerr << "GC_R3_PERF_ERROR|remove|" << remove_error.message()
                      << '\n';
            return false;
        }
    }

    const auto started = Clock::now();
    auto result = kasumi::application::detail::run_sync(fixture.context);
    const auto wall_us = elapsed_us(started);
    if (!result) {
        std::cerr << "GC_R3_PERF_ERROR|sync|" << result.error().detail << '\n';
        return false;
    }
    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&result->data);
    if (summary == nullptr) {
        return false;
    }
    if (phase == "setup") {
        if (!summary->published ||
            fixture.counts.content_puts != fixture.content_ids) {
            std::cerr << "GC_R3_PERF_ERROR|setup-semantics\n";
            return false;
        }
    }
    if (phase == "noop" || phase == "repaired_noop") {
        if (summary->total != 0 || summary->uploaded != 0 ||
            summary->published || summary->partial ||
            fixture.counts.content_puts != 0) {
            std::cerr << "GC_R3_PERF_ERROR|noop-semantics\n";
            return false;
        }
    }
    if (phase == "repair") {
        if (summary->published || summary->partial ||
            fixture.counts.content_puts != 1) {
            std::cerr << "GC_R3_PERF_ERROR|repair-semantics\n";
            return false;
        }
    }
    const auto metric = [](std::string_view name) {
        return kasumi::platform::perf_trace::get_count(name);
    };
    const auto metric_time = [](std::string_view name) {
        return kasumi::platform::perf_trace::get_time(name);
    };
    std::cout << "GC_R3_PERF|phase=" << phase << "|files=" << fixture.files
              << "|content_ids=" << fixture.content_ids
              << "|wall_us=" << wall_us
              << "|scan_us=" << metric_time("local filesystem scan wall")
              << "|scan_calls=" << metric("local scanner invocations")
              << "|hash_calls=" << metric("local hash file calls")
              << "|hash_bytes=" << metric("local hash bytes")
              << "|cache_hits=" << metric("local hash cache hits")
              << "|availability_us=" << metric_time("content availability")
              << "|reobservation_us=" << metric_time("reobservation")
              << "|presence_ids="
              << metric("sync content availability identifiers")
              << "|presence_checks=" << fixture.counts.presences
              << "|presence_batches=" << fixture.counts.control_batches
              << "|batch_ids=" << fixture.counts.control_batch_ids
              << "|list_calls=" << fixture.counts.lists
              << "|get_calls=" << fixture.counts.gets
              << "|puts=" << fixture.counts.puts
              << "|content_puts=" << fixture.counts.content_puts
              << "|physical_hashes=" << fixture.counts.physical_hashes
              << "|total=" << summary->total
              << "|uploaded=" << summary->uploaded
              << "|published=" << (summary->published ? 1 : 0)
              << "|partial=" << (summary->partial ? 1 : 0) << '\n';
    return true;
}

} // namespace

int main(int argc, char** argv) {
    kasumi::platform::perf_trace::force_enable(true);
    if (argc < 2) {
        std::cerr << "usage: kasumi_benchmark_sync_availability ROOT [FILES] "
                     "[CONTENT_IDS]\n";
        return 2;
    }
    const std::filesystem::path root = argv[1];
    const auto files =
        argc > 2 ? static_cast<std::size_t>(std::stoull(argv[2])) : 1'000;
    const auto content_ids =
        argc > 3 ? static_cast<std::size_t>(std::stoull(argv[3])) : 100;

    Fixture fixture;
    if (!create_fixture(root, files, content_ids, fixture)) {
        std::cerr << "GC_R3_PERF_ERROR|fixture\n";
        return 1;
    }
    if (!run_phase(fixture, "setup", false, 0) ||
        !run_phase(fixture, "noop", false, 0) ||
        !run_phase(fixture, "repair", true, 0) ||
        !run_phase(fixture, "repaired_noop", false, 0)) {
        return 1;
    }
    return 0;
}
