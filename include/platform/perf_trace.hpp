#ifndef KASUMI_PLATFORM_PERF_TRACE_HPP
#define KASUMI_PLATFORM_PERF_TRACE_HPP

#include <chrono>
#include <cstdint>
#include <string_view>

namespace kasumi::platform::perf_trace {

struct Token {
    std::chrono::steady_clock::time_point started{};
    bool active = false;
};

bool enabled() noexcept;
void force_enable(bool state) noexcept;
void reset() noexcept;
Token begin() noexcept;
void finish(std::string_view name, Token token) noexcept;
void count(std::string_view name, std::uint64_t amount = 1) noexcept;
std::uint64_t get_count(std::string_view name) noexcept;
void report(std::string_view outcome) noexcept;

} // namespace kasumi::platform::perf_trace

#endif
