#include "platform/perf_trace.hpp"

#include <algorithm>
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
bool forced_enable_state = false;

} // namespace

bool enabled() noexcept {
    static const bool value = [] {
        const char* setting = std::getenv("KASUMI_PERF_TRACE");
        return setting != nullptr && std::string_view{setting} == "1";
    }();
    return value || forced_enable_state;
}

void force_enable(bool state) noexcept {
    forced_enable_state = state;
}

void reset() noexcept {
    if (!enabled())
        return;
    try {
        std::lock_guard lock(metrics_mutex);
        metrics.clear();
    } catch (...) {
    }
}

Token begin() noexcept {
    return enabled() ? Token{.started = std::chrono::steady_clock::now(),
                             .active = true}
                     : Token{};
}

void finish(std::string_view name, Token token) noexcept {
    if (!token.active || name.empty())
        return;
    const auto elapsed = std::chrono::steady_clock::now() - token.started;
    try {
        std::lock_guard lock(metrics_mutex);
        auto& metric = metrics[std::string{name}];
        ++metric.calls;
        metric.elapsed += elapsed;
    } catch (...) {
    }
}

void count(std::string_view name, std::uint64_t amount) noexcept {
    if (!enabled() || name.empty())
        return;
    try {
        std::lock_guard lock(metrics_mutex);
        metrics[std::string{name}].calls += amount;
    } catch (...) {
    }
}

std::uint64_t get_count(std::string_view name) noexcept {
    if (!enabled() || name.empty())
        return 0;
    try {
        std::lock_guard lock(metrics_mutex);
        const auto it = metrics.find(std::string{name});
        return it != metrics.end() ? it->second.calls : 0;
    } catch (...) {
        return 0;
    }
}

std::uint64_t get_time(std::string_view name) noexcept {
    if (!enabled() || name.empty())
        return 0;
    try {
        std::lock_guard lock(metrics_mutex);
        const auto it = metrics.find(std::string{name});
        return it != metrics.end() ? static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(it->second.elapsed).count()) : 0;
    } catch (...) {
        return 0;
    }
}

void maximum(std::string_view name, std::uint64_t value) noexcept {
    if (!enabled() || name.empty())
        return;
    try {
        std::lock_guard lock(metrics_mutex);
        auto& metric = metrics[std::string{name}];
        metric.calls = std::max(metric.calls, value);
    } catch (...) {
    }
}

void report(std::string_view outcome) noexcept {
    if (!enabled())
        return;
    try {
        std::lock_guard lock(metrics_mutex);
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
    } catch (...) {
    }
}

} // namespace kasumi::platform::perf_trace
