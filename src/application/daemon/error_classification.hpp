#ifndef KASUMI_APPLICATION_DAEMON_ERROR_CLASSIFICATION_HPP
#define KASUMI_APPLICATION_DAEMON_ERROR_CLASSIFICATION_HPP

#include "application/result.hpp"

#include <optional>
#include <string_view>

namespace kasumi::application::daemon_detail {

// Extracts the rclone remote name (e.g. "gdrive" from "gdrive:path") when
// remote_dir targets an rclone remote, or std::nullopt for local paths.
std::optional<std::string_view>
extract_rclone_remote_name(std::string_view remote_dir) noexcept;

// Returns true when sync aborted because local files mutated mid-flight while
// a sync was already executing (materialization mismatch or concurrent edit).
bool is_concurrent_local_mutation_error(const Error& error) noexcept;

// Classifies whether a failed daemon sync should schedule bounded exponential
// backoff rather than tripping a permanent NeedsAttention circuit breaker.
bool is_transient_sync_error(const Error& error) noexcept;

} // namespace kasumi::application::daemon_detail

#endif
