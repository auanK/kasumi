#ifndef KASUMI_APPLICATION_CONCURRENCY_HPP
#define KASUMI_APPLICATION_CONCURRENCY_HPP

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <thread>
#include <utility>
#include <vector>

namespace kasumi::application {

constexpr std::size_t default_content_concurrency = 8;
constexpr std::size_t maximum_experimental_content_concurrency = 16;

// Resolves configured transfer concurrency from KASUMI_CONTENT_CONCURRENCY.
// Returns default_content_concurrency (8) when unset or invalid.
// Caps at maximum_experimental_content_concurrency (16).
std::size_t content_concurrency() noexcept;

template <typename Fn>
void parallel_for_indexed(std::size_t count, std::size_t parallelism, Fn&& fn) {
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
    std::atomic<std::size_t> next{0};
    std::vector<std::jthread> workers;
    workers.reserve(worker_count);
    for (std::size_t w = 0; w < worker_count; ++w) {
        workers.emplace_back([&]() {
            while (true) {
                const auto index = next.fetch_add(1, std::memory_order_relaxed);
                if (index >= count) {
                    break;
                }
                fn(index);
            }
        });
    }
}

} // namespace kasumi::application

#endif
