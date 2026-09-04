#ifndef KASUMI_PLATFORM_PERF_TRACE_HPP
#define KASUMI_PLATFORM_PERF_TRACE_HPP

#include <chrono>
#include <cstdint>
#include <string_view>

namespace kasumi::platform::perf_trace {

// Marks the optional start of a measurement.
struct Token {
    std::chrono::steady_clock::time_point started{};
    // Indicates whether the measurement should be recorded.
    bool active = false;
};

// Indicates whether KASUMI_PERF_TRACE=1 enabled tracing.
bool enabled() noexcept;
// Overrides trace collection state at runtime (tests only).
void force_enable(bool state) noexcept;
// Clears accumulated metrics.
void reset() noexcept;
// Begins a duration measurement.
Token begin() noexcept;
// Records duration associated with name.
void finish(std::string_view name, Token token) noexcept;
// Adds amount to the named counter.
void count(std::string_view name, std::uint64_t amount = 1) noexcept;
// Returns value of the named counter.
std::uint64_t get_count(std::string_view name) noexcept;
// Returns accumulated duration (in microseconds) for the named counter.
std::uint64_t get_time(std::string_view name) noexcept;
// Tracks maximum observed value for name.
void maximum(std::string_view name, std::uint64_t value) noexcept;
// Prints accumulated metrics and the reported outcome.
void report(std::string_view outcome) noexcept;

} // namespace kasumi::platform::perf_trace

#endif
