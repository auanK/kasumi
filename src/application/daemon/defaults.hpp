#ifndef KASUMI_APPLICATION_DAEMON_DEFAULTS_HPP
#define KASUMI_APPLICATION_DAEMON_DEFAULTS_HPP

#include <cstdint>

namespace kasumi::application::daemon_detail {

inline constexpr std::uint32_t kDaemonApiVersion = 1U;
inline constexpr std::uint32_t kDefaultSyncIntervalSeconds = 300U;

} // namespace kasumi::application::daemon_detail

#endif
