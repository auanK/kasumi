#ifndef KASUMI_APPLICATION_CONCURRENCY_HPP
#define KASUMI_APPLICATION_CONCURRENCY_HPP

#include "platform/cancellation.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <functional>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

namespace kasumi::application {

constexpr std::size_t default_content_concurrency = 8;
constexpr std::size_t maximum_experimental_content_concurrency = 16;

// Resolves effective transfer concurrency from request override,
// KASUMI_CONTENT_CONCURRENCY environment variable, profile override, or
// default.
std::size_t resolve_content_concurrency(
    std::optional<std::size_t> request_override = std::nullopt,
    std::optional<std::size_t> profile_override = std::nullopt) noexcept;

// Returns the active scoped transfer concurrency or falls back to
// KASUMI_CONTENT_CONCURRENCY / default_content_concurrency (8).
std::size_t content_concurrency() noexcept;

std::optional<std::size_t> current_content_concurrency_override() noexcept;

struct ScopedContentConcurrency {
    std::optional<std::size_t> previous{};

    explicit ScopedContentConcurrency(
        std::optional<std::size_t> override_value) noexcept;
    ~ScopedContentConcurrency() noexcept;

    ScopedContentConcurrency(const ScopedContentConcurrency&) = delete;
    ScopedContentConcurrency&
    operator=(const ScopedContentConcurrency&) = delete;
};

namespace testing {

using WorkerSpawnHook = std::function<void(std::size_t worker_index)>;

struct ScopedWorkerSpawnHook {
    WorkerSpawnHook previous{};

    explicit ScopedWorkerSpawnHook(WorkerSpawnHook hook);
    ~ScopedWorkerSpawnHook() noexcept;

    ScopedWorkerSpawnHook(const ScopedWorkerSpawnHook&) = delete;
    ScopedWorkerSpawnHook& operator=(const ScopedWorkerSpawnHook&) = delete;
};

void invoke_worker_spawn_hook(std::size_t worker_index);

} // namespace testing

template <typename Fn, typename OnSpawnError>
void parallel_for_indexed(std::size_t count,
                          std::size_t parallelism,
                          Fn&& fn,
                          OnSpawnError&& on_spawn_error) {
    if (count == 0) {
        return;
    }
    const auto worker_count =
        std::min(std::max<std::size_t>(1, parallelism), count);
    if (worker_count == 1) {
        for (std::size_t i = 0; i < count; ++i) {
            fn(i);
        }
        return;
    }
    const auto stop_token = platform::cancellation::current_stop_token();
    const auto concurrency_override = current_content_concurrency_override();
    std::atomic<std::size_t> next{0};
    std::vector<std::jthread> workers;
    try {
        workers.reserve(worker_count);
        for (std::size_t w = 0; w < worker_count; ++w) {
            testing::invoke_worker_spawn_hook(w);
            workers.emplace_back([&, stop_token, concurrency_override]() {
                const platform::cancellation::ScopedStopToken stop_scope{
                    stop_token};
                const ScopedContentConcurrency concurrency_scope{
                    concurrency_override};
                while (true) {
                    const auto index =
                        next.fetch_add(1, std::memory_order_relaxed);
                    if (index >= count) {
                        break;
                    }
                    fn(index);
                }
            });
        }
    } catch (...) {
        next.store(count, std::memory_order_relaxed);
        try {
            on_spawn_error();
        } catch (...) {
        }
        throw;
    }
}

template <typename Fn>
void parallel_for_indexed(std::size_t count,
                          std::size_t parallelism,
                          Fn&& fn) {
    parallel_for_indexed(
        count, parallelism, std::forward<Fn>(fn), []() noexcept {});
}

} // namespace kasumi::application

#endif
