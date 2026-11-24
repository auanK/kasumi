#ifndef KASUMI_APPLICATION_PROGRESS_HPP
#define KASUMI_APPLICATION_PROGRESS_HPP

#include "application/execute.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace kasumi::application {

struct ProgressMeter;

inline void emit_progress_snapshot(ProgressMeter& meter) noexcept;
inline void emit_pending_progress(ProgressMeter& meter) noexcept;

// Workers touch only the counters. One sampler delivers snapshots and stage
// transitions to the same callback in order.
struct ProgressMeter {
    const ProgressCallback& callback;
    transport::Transport& storage;
    transport::TransferMetrics* previous = nullptr;
    std::mutex gate;
    std::condition_variable_any wake;
    std::optional<ActivityProgress> activity;
    std::optional<SyncProgress> applying;
    std::uint32_t reported_applied = 0;
    std::uint64_t stage_id = 0;
    std::uint64_t start_bytes = 0;
    std::uint64_t start_objects = 0;
    std::uint64_t start_total_bytes = 0;
    std::uint64_t start_total_objects = 0;
    transport::TransferMetrics wire;
    std::atomic<std::uint64_t> files_seen{0};
    std::atomic<std::uint64_t> files_hashed{0};
    std::atomic<std::uint64_t> cache_hits{0};
    std::atomic<std::uint64_t> disk_bytes{0};
    std::atomic<std::uint64_t> files_bytes{0};
    std::atomic<bool> observing_remote{false};
    std::atomic<std::uint64_t> work{0};
    std::atomic<std::uint64_t> raw_bytes{0};
    std::atomic<std::uint64_t> staged_bytes{0};
    std::atomic<std::uint64_t> bytes_reused{0};
    std::jthread sampler;

    ProgressMeter(const ProgressCallback& cb,
                  transport::Transport& storage_ref,
                  bool count_transfers = true) noexcept
        : callback(cb), storage(storage_ref), previous(storage_ref.metrics) {
        if (count_transfers) {
            storage.metrics = &wire;
        }
        if (callback) {
            try {
                sampler = std::jthread([this](std::stop_token stop) {
                    std::unique_lock lock(gate);
                    while (!stop.stop_requested()) {
                        wake.wait_for(
                            lock, stop, std::chrono::milliseconds(200), [] {
                                return false;
                            });
                        if (!stop.stop_requested()) {
                            emit_pending_progress(*this);
                        }
                    }
                });
            } catch (...) {
            }
        }
    }

    ~ProgressMeter() {
        sampler = {};
        emit_pending_progress(*this);
        storage.metrics = previous;
    }

    ProgressMeter(const ProgressMeter&) = delete;
    ProgressMeter& operator=(const ProgressMeter&) = delete;
};

inline void progress_add(std::atomic<std::uint64_t>& counter,
                         std::uint64_t value = 1) noexcept {
    counter.fetch_add(value, std::memory_order_relaxed);
}

inline bool is_progress_observing(const ProgressMeter& meter) noexcept {
    return static_cast<bool>(meter.callback);
}

inline void emit_progress_snapshot(ProgressMeter& meter) noexcept try {
    auto event = *meter.activity;
    switch (event.activity) {
        case Activity::Scanning:
        case Activity::Reobserving:
            event.cache_hits = meter.cache_hits.load(std::memory_order_relaxed);
            event.files_hashed =
                meter.files_hashed.load(std::memory_order_relaxed);
            event.objects = event.cache_hits + event.files_hashed;
            event.total_objects =
                meter.files_seen.load(std::memory_order_relaxed);
            event.bytes = meter.disk_bytes.load(std::memory_order_relaxed);
            event.total_bytes =
                meter.files_bytes.load(std::memory_order_relaxed);
            event.observing_remote =
                meter.observing_remote.load(std::memory_order_relaxed);
            break;
        case Activity::Uploading:
        case Activity::Downloading:
        case Activity::Auditing: {
            const auto& direction = event.activity == Activity::Uploading
                                        ? meter.wire.upload
                                        : meter.wire.download;
            event.bytes = direction.bytes.load(std::memory_order_relaxed) -
                          meter.start_bytes;
            event.objects =
                event.activity == Activity::Auditing
                    ? meter.work.load(std::memory_order_relaxed)
                    : direction.objects.load(std::memory_order_relaxed) -
                          meter.start_objects;
            const auto total =
                direction.known_total_bytes.load(std::memory_order_relaxed) -
                meter.start_total_bytes;
            const auto known_objects =
                direction.known_total_objects.load(std::memory_order_relaxed) -
                meter.start_total_objects;
            if (event.total_bytes && event.bytes > *event.total_bytes) {
                event.total_bytes.reset();
            } else if (!event.total_bytes && total > 0 &&
                       total >= event.bytes &&
                       (!event.total_objects ||
                        known_objects >= *event.total_objects)) {
                event.total_bytes = total;
            }
            event.bytes_reused =
                meter.bytes_reused.load(std::memory_order_relaxed);
            break;
        }
        case Activity::Staging:
            event.staged_bytes =
                meter.staged_bytes.load(std::memory_order_relaxed);
            [[fallthrough]];
        default:
            event.objects = meter.work.load(std::memory_order_relaxed);
            event.bytes = meter.raw_bytes.load(std::memory_order_relaxed);
            break;
    }
    report_progress(meter.callback, event);
} catch (...) {
}

inline void emit_pending_progress(ProgressMeter& meter) noexcept {
    if (meter.activity) {
        emit_progress_snapshot(meter);
    }
    if (meter.applying &&
        *meter.applying->applied_items != meter.reported_applied) {
        meter.reported_applied = *meter.applying->applied_items;
        report_progress(meter.callback, *meter.applying);
    }
}

inline void notify_progress(ProgressMeter& meter,
                            const ExecutionProgress& event) noexcept {
    if (meter.callback) {
        std::lock_guard lock(meter.gate);
        emit_pending_progress(meter);
        meter.activity.reset();
        meter.applying.reset();
        if (const auto* sync = std::get_if<SyncProgress>(&event);
            sync && sync->stage == SyncStage::Applying &&
            sync->total_items > 0) {
            meter.applying = SyncProgress{.stage = SyncStage::Applying,
                                          .total_items = sync->total_items,
                                          .applied_items = 0};
            meter.reported_applied = 0;
        }
        report_progress(meter.callback, event);
    }
}

inline void
begin_progress_phase(ProgressMeter& meter,
                     Activity phase,
                     std::optional<std::uint64_t> total = std::nullopt,
                     unsigned attempt = 0,
                     const std::filesystem::path* item = nullptr) noexcept {
    if (!meter.callback) {
        return;
    }
    std::lock_guard lock(meter.gate);
    emit_pending_progress(meter);
    // A fully staged upload has a byte total before transport starts.
    const auto upload_bytes =
        phase == Activity::Uploading && meter.activity &&
                meter.activity->activity == Activity::Staging && total &&
                meter.work.load(std::memory_order_relaxed) == *total
            ? std::optional{meter.staged_bytes.load(std::memory_order_relaxed)}
            : std::nullopt;
    meter.activity = ActivityProgress{.activity = phase,
                                      .total_bytes = upload_bytes,
                                      .total_objects = total,
                                      .attempt = attempt,
                                      .stage_id = ++meter.stage_id};
    if (item) {
        try {
            meter.activity->item_path = *item;
        } catch (...) {
        }
    }
    meter.work.store(0, std::memory_order_relaxed);
    meter.raw_bytes.store(0, std::memory_order_relaxed);
    meter.staged_bytes.store(0, std::memory_order_relaxed);
    if (phase == Activity::Scanning || phase == Activity::Reobserving) {
        meter.files_seen.store(0, std::memory_order_relaxed);
        meter.files_hashed.store(0, std::memory_order_relaxed);
        meter.cache_hits.store(0, std::memory_order_relaxed);
        meter.disk_bytes.store(0, std::memory_order_relaxed);
        meter.files_bytes.store(0, std::memory_order_relaxed);
        meter.observing_remote.store(false, std::memory_order_relaxed);
    }
    const auto& direction =
        phase == Activity::Uploading ? meter.wire.upload : meter.wire.download;
    meter.start_bytes = direction.bytes.load(std::memory_order_relaxed);
    meter.start_objects = direction.objects.load(std::memory_order_relaxed);
    meter.start_total_bytes =
        direction.known_total_bytes.load(std::memory_order_relaxed);
    meter.start_total_objects =
        direction.known_total_objects.load(std::memory_order_relaxed);
    emit_progress_snapshot(meter);
}

inline void record_progress_applied(ProgressMeter& meter,
                                    std::size_t count) noexcept {
    if (!meter.callback || count == 0) {
        return;
    }
    std::lock_guard lock(meter.gate);
    if (meter.applying) {
        auto& completed = *meter.applying->applied_items;
        completed += static_cast<std::uint32_t>(std::min<std::size_t>(
            count, meter.applying->total_items - completed));
    }
}

inline void update_progress_transfer_item(
    ProgressMeter& meter,
    const std::filesystem::path& path,
    const std::optional<transport::TransferItemProgress>& item) noexcept try {
    std::lock_guard lock(meter.gate);
    if (!meter.activity || meter.activity->activity != Activity::Uploading) {
        return;
    }
    if (!item) {
        meter.activity->item_path.clear();
        meter.activity->item_bytes.reset();
        meter.activity->item_total_bytes.reset();
        return;
    }
    if (meter.activity->item_path.empty()) {
        meter.activity->item_path = path;
    }
    meter.activity->item_bytes = item->bytes;
    meter.activity->item_total_bytes = item->total_bytes;
} catch (...) {
}

inline void record_progress_staged(ProgressMeter& meter,
                                   const std::filesystem::path& path,
                                   std::uint64_t original) noexcept {
    if (meter.callback) {
        std::error_code error;
        const auto size = std::filesystem::file_size(path, error);
        if (!error) {
            progress_add(meter.raw_bytes, original);
            progress_add(meter.staged_bytes, size);
            progress_add(meter.work);
        }
    }
}

} // namespace kasumi::application

#endif
