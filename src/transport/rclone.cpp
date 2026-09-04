#include "detail.hpp"
#include "rclone/detail.hpp"

#include <utility>

namespace kasumi::transport {
namespace detail {

std::expected<Transport, Error>
open_rclone_backend(RcloneConfiguration configuration) {
    auto state = rclone_detail::start_state(std::move(configuration));
    if (!state) {
        return std::unexpected(state.error());
    }

    return Transport{
        .state = TransportStateHandle{*state, rclone_detail::destroy_state},
        .storage = rclone_detail::make_storage_operations(),
    };
}

} // namespace detail
} // namespace kasumi::transport
