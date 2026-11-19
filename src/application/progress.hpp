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

// Workers touch only the counters. One sampler delivers snapshots and stage
// transitions to the same callback in order.
class ProgressMeter {
public:
    ProgressMeter(const ProgressCallback& callback,
                  transport::Transport& storage,
                  bool count_transfers = true) noexcept
        : callback_(callback), storage_(storage), previous_(storage.metrics) {
        if (count_transfers) {
            storage_.metrics = &wire;
        }
        if (callback_) {
            try {
                sampler_ = std::jthread([this](std::stop_token stop) {
                    std::unique_lock lock(gate_);
                    while (!stop.stop_requested()) {
                        wake_.wait_for(
                            lock, stop, std::chrono::milliseconds(200), [] {
                                return false;
                            });
                        if (!stop.stop_requested()) {
                            emit_pending();
                        }
                    }
                });
            } catch (...) {
            }
        }
    }

    ~ProgressMeter() {
        sampler_ = {};
        emit_pending();
        storage_.metrics = previous_;
    }

    void notify(const ExecutionProgress& event) noexcept {
        if (callback_) {
            std::lock_guard lock(gate_);
            emit_pending();
            activity_.reset();
            applying_.reset();
            if (const auto* sync = std::get_if<SyncProgress>(&event);
                sync && sync->stage == SyncStage::Applying &&
                sync->total_items > 0) {
                applying_ = SyncProgress{.stage = SyncStage::Applying,
                                         .total_items = sync->total_items,
                                         .applied_items = 0};
                reported_applied_ = 0;
            }
            report_progress(callback_, event);
        }
    }

    void phase(Activity phase,
               std::optional<std::uint64_t> total = std::nullopt,
               unsigned attempt = 0,
               const std::filesystem::path* item = nullptr) noexcept {
        if (!callback_) {
            return;
        }
        std::lock_guard lock(gate_);
        emit_pending();
        // A fully staged upload has a byte total before transport starts.
        const auto upload_bytes =
            phase == Activity::Uploading && activity_ &&
                    activity_->activity == Activity::Staging && total &&
                    work.load(std::memory_order_relaxed) == *total
                ? std::optional{staged_bytes.load(std::memory_order_relaxed)}
                : std::nullopt;
        activity_ = ActivityProgress{.activity = phase,
                                     .total_bytes = upload_bytes,
                                     .total_objects = total,
                                     .attempt = attempt,
                                     .stage_id = ++stage_id_};
        if (item) {
            try {
                activity_->item_path = *item;
            } catch (...) {
            }
        }
        work.store(0, std::memory_order_relaxed);
        raw_bytes.store(0, std::memory_order_relaxed);
        staged_bytes.store(0, std::memory_order_relaxed);
        if (phase == Activity::Scanning || phase == Activity::Reobserving) {
            files_seen.store(0, std::memory_order_relaxed);
            files_hashed.store(0, std::memory_order_relaxed);
            cache_hits.store(0, std::memory_order_relaxed);
            disk_bytes.store(0, std::memory_order_relaxed);
            files_bytes.store(0, std::memory_order_relaxed);
            observing_remote.store(false, std::memory_order_relaxed);
        }
        const auto& direction =
            phase == Activity::Uploading ? wire.upload : wire.download;
        start_bytes_ = direction.bytes.load(std::memory_order_relaxed);
        start_objects_ = direction.objects.load(std::memory_order_relaxed);
        start_total_bytes_ =
            direction.known_total_bytes.load(std::memory_order_relaxed);
        start_total_objects_ =
            direction.known_total_objects.load(std::memory_order_relaxed);
        emit();
    }

    void applied(std::size_t count) noexcept {
        if (!callback_ || count == 0) {
            return;
        }
        std::lock_guard lock(gate_);
        if (applying_) {
            auto& completed = *applying_->applied_items;
            completed += static_cast<std::uint32_t>(std::min<std::size_t>(
                count, applying_->total_items - completed));
        }
    }

    bool observing() const noexcept {
        return static_cast<bool>(callback_);
    }

    void transfer_item(
        const std::filesystem::path& path,
        const std::optional<transport::TransferItemProgress>& item) noexcept
        try {
        std::lock_guard lock(gate_);
        if (!activity_ || activity_->activity != Activity::Uploading) {
            return;
        }
        if (!item) {
            activity_->item_path.clear();
            activity_->item_bytes.reset();
            activity_->item_total_bytes.reset();
            return;
        }
        if (activity_->item_path.empty()) {
            activity_->item_path = path;
        }
        activity_->item_bytes = item->bytes;
        activity_->item_total_bytes = item->total_bytes;
    } catch (...) {
    }

    static void add(std::atomic<std::uint64_t>& counter,
                    std::uint64_t value = 1) noexcept {
        counter.fetch_add(value, std::memory_order_relaxed);
    }

    void record_staged(const std::filesystem::path& path,
                       std::uint64_t original) noexcept {
        if (callback_) {
            std::error_code error;
            const auto size = std::filesystem::file_size(path, error);
            if (!error) {
                add(raw_bytes, original);
                add(staged_bytes, size);
                add(work);
            }
        }
    }

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

private:
    void emit_pending() noexcept {
        if (activity_) {
            emit();
        }
        if (applying_ && *applying_->applied_items != reported_applied_) {
            reported_applied_ = *applying_->applied_items;
            report_progress(callback_, *applying_);
        }
    }

    void emit() noexcept try {
        auto event = *activity_;
        switch (event.activity) {
            case Activity::Scanning:
            case Activity::Reobserving:
                event.cache_hits = cache_hits.load(std::memory_order_relaxed);
                event.files_hashed =
                    files_hashed.load(std::memory_order_relaxed);
                event.objects = event.cache_hits + event.files_hashed;
                event.total_objects =
                    files_seen.load(std::memory_order_relaxed);
                event.bytes = disk_bytes.load(std::memory_order_relaxed);
                event.total_bytes = files_bytes.load(std::memory_order_relaxed);
                event.observing_remote =
                    observing_remote.load(std::memory_order_relaxed);
                break;
            case Activity::Uploading:
            case Activity::Downloading:
            case Activity::Auditing: {
                const auto& direction = event.activity == Activity::Uploading
                                            ? wire.upload
                                            : wire.download;
                event.bytes = direction.bytes.load(std::memory_order_relaxed) -
                              start_bytes_;
                event.objects =
                    event.activity == Activity::Auditing
                        ? work.load(std::memory_order_relaxed)
                        : direction.objects.load(std::memory_order_relaxed) -
                              start_objects_;
                const auto total = direction.known_total_bytes.load(
                                       std::memory_order_relaxed) -
                                   start_total_bytes_;
                const auto known_objects = direction.known_total_objects.load(
                                               std::memory_order_relaxed) -
                                           start_total_objects_;
                if (event.total_bytes && event.bytes > *event.total_bytes) {
                    event.total_bytes.reset();
                } else if (!event.total_bytes && total > 0 &&
                           total >= event.bytes &&
                           (!event.total_objects ||
                            known_objects >= *event.total_objects)) {
                    event.total_bytes = total;
                }
                event.bytes_reused =
                    bytes_reused.load(std::memory_order_relaxed);
                break;
            }
            case Activity::Staging:
                event.staged_bytes =
                    staged_bytes.load(std::memory_order_relaxed);
                [[fallthrough]];
            default:
                event.objects = work.load(std::memory_order_relaxed);
                event.bytes = raw_bytes.load(std::memory_order_relaxed);
                break;
        }
        report_progress(callback_, event);
    } catch (...) {
    }

    const ProgressCallback& callback_;
    transport::Transport& storage_;
    transport::TransferMetrics* previous_;
    std::mutex gate_;
    std::condition_variable_any wake_;
    std::optional<ActivityProgress> activity_;
    std::optional<SyncProgress> applying_;
    std::uint32_t reported_applied_ = 0;
    std::uint64_t stage_id_ = 0;
    std::uint64_t start_bytes_ = 0;
    std::uint64_t start_objects_ = 0;
    std::uint64_t start_total_bytes_ = 0;
    std::uint64_t start_total_objects_ = 0;
    std::jthread sampler_;
};

} // namespace kasumi::application

#endif
