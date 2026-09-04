#ifndef KASUMI_APPLICATION_OBSERVATION_HISTORY_DETAIL_HPP
#define KASUMI_APPLICATION_OBSERVATION_HISTORY_DETAIL_HPP

#include "application/observation/history.hpp"

#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <unordered_set>

namespace kasumi::application::observation::history::detail {

// Filters and bounds physical content identifiers.
std::expected<std::unordered_set<std::string>, Error>
collect_content_identifiers(std::span<const std::string> identifiers,
                            std::size_t maximum_count);

} // namespace kasumi::application::observation::history::detail

#endif
