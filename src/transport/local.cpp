#include "detail.hpp"
#include "local/detail.hpp"

#include <new>
#include <utility>

namespace kasumi::transport {
namespace {

std::expected<void, Error>
validate_destination(const std::filesystem::path& root) {
    auto candidate = root;
    for (;;) {
        std::error_code error;
        const auto status = std::filesystem::status(candidate, error);
        if (error && error != std::errc::no_such_file_or_directory &&
            error != std::errc::not_a_directory) {
            return std::unexpected(local_detail::make_error(error));
        }
        if (!error && std::filesystem::exists(status)) {
            if (!std::filesystem::is_directory(status)) {
                return std::unexpected(Error{
                    .code = ErrorCode::InvalidContext,
                    .message = "local destination traverses a file",
                    .native_code = 0,
                });
            }
            return {};
        }
        const auto parent = candidate.parent_path();
        if (parent.empty() || parent == candidate) {
            return std::unexpected(Error{
                .code = ErrorCode::StorageNotFound,
                .message = "local destination root is not available",
                .native_code = error.value(),
            });
        }
        candidate = parent;
    }
}

void destroy_local_state(void* context) noexcept {
    delete static_cast<local_detail::State*>(context);
}

} // namespace

std::expected<Transport, Error>
detail::open_local_backend(detail::LocalConfiguration configuration) {
    if (configuration.root.empty()) {
        return std::unexpected(Error{
            .code = ErrorCode::InvalidContext,
            .message = "storage path is invalid",
            .native_code = 0,
        });
    }
    if (auto valid = validate_destination(configuration.root); !valid) {
        return std::unexpected(valid.error());
    }

    auto* state = new (std::nothrow)
        local_detail::State{.root = std::move(configuration.root)};
    if (state == nullptr) {
        return std::unexpected(Error{
            .code = ErrorCode::Io,
            .message = "could not allocate local state",
            .native_code = 0,
        });
    }

    return Transport{
        .state = TransportStateHandle{state, destroy_local_state},
        .storage = local_detail::make_storage_operations(),
    };
}

} // namespace kasumi::transport
