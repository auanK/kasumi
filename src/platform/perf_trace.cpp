#include "platform/perf_trace.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <string>

namespace kasumi::platform::perf_trace {
namespace {

struct Metric {
    std::uint64_t calls = 0;
    std::chrono::steady_clock::duration elapsed{};
};

std::mutex metrics_mutex;
std::map<std::string, Metric> metrics;
std::atomic<bool> forced_enable_state{false};

template <typename Fn> void with_metrics(bool active, Fn&& fn) noexcept {
    if (!active) {
        return;
    }
    try {
        std::lock_guard lock(metrics_mutex);
        fn();
    } catch (...) {
    }
}

} // namespace

bool enabled() noexcept {
    static const bool value = [] {
        const char* setting = std::getenv("KASUMI_PERF_TRACE");
        return setting != nullptr && std::string_view{setting} == "1";
    }();
    return value || forced_enable_state.load(std::memory_order_relaxed);
}

void force_enable(bool state) noexcept {
    forced_enable_state.store(state, std::memory_order_relaxed);
}

void reset() noexcept {
    with_metrics(enabled(), [] {
        metrics.clear();
    });
}

Token begin() noexcept {
    return enabled() ? Token{.started = std::chrono::steady_clock::now(),
                             .active = true}
                     : Token{};
}

void finish(std::string_view name, Token token) noexcept {
    if (!token.active || name.empty()) {
        return;
    }
    const auto elapsed = std::chrono::steady_clock::now() - token.started;
    with_metrics(true, [&] {
        auto& metric = metrics[std::string{name}];
        ++metric.calls;
        metric.elapsed += elapsed;
    });
}

void count(std::string_view name, std::uint64_t amount) noexcept {
    with_metrics(enabled() && !name.empty(), [&] {
        metrics[std::string{name}].calls += amount;
    });
}

std::uint64_t get_count(std::string_view name) noexcept {
    std::uint64_t calls = 0;
    with_metrics(enabled() && !name.empty(), [&] {
        if (const auto it = metrics.find(std::string{name});
            it != metrics.end()) {
            calls = it->second.calls;
        }
    });
    return calls;
}

void report(std::string_view outcome) noexcept {
    with_metrics(enabled(), [&] {
        for (const auto& [name, metric] : metrics) {
            const auto microseconds =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    metric.elapsed)
                    .count();
            std::fprintf(stderr,
                         "KASUMI_PERF name=%s calls=%llu total_us=%lld\n",
                         name.c_str(),
                         static_cast<unsigned long long>(metric.calls),
                         static_cast<long long>(microseconds));
        }
        std::fprintf(stderr,
                     "KASUMI_PERF outcome=%.*s\n",
                     static_cast<int>(outcome.size()),
                     outcome.data());
        std::fflush(stderr);
    });
}

} // namespace kasumi::platform::perf_trace
