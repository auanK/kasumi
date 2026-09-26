#ifndef KASUMI_APPLICATION_CONCURRENCY_HPP
#define KASUMI_APPLICATION_CONCURRENCY_HPP

#include <cstddef>

namespace kasumi::application {

constexpr std::size_t default_content_concurrency = 8;
constexpr std::size_t maximum_experimental_content_concurrency = 16;

// Resolves configured transfer concurrency from KASUMI_CONTENT_CONCURRENCY.
// Returns default_content_concurrency (8) when unset or invalid.
// Caps at maximum_experimental_content_concurrency (16).
std::size_t content_concurrency() noexcept;

} // namespace kasumi::application

#endif
