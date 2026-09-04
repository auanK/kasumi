#ifndef KASUMI_TRANSPORT_LOCAL_DETAIL_HPP
#define KASUMI_TRANSPORT_LOCAL_DETAIL_HPP

#include "transport/transport.hpp"

#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace kasumi::transport::local_detail {

// Local transport state.
struct State {
    std::filesystem::path root;
};

// Converts opaque context to local transport state.
State* local_state(void* context) noexcept;

// Converts native error; uses fallback code if unmapped.
Error make_error(const std::error_code& error,
                 ErrorCode fallback = ErrorCode::Io);

// Creates default error for missing context.
Error invalid_context_error();
// Creates default error for invalid identifier.
Error invalid_identifier_error();

// Returns the physical objects directory.
std::filesystem::path objects_directory(const State& state);

// Builds the storage operations table for the local transport.
StorageOperations make_storage_operations() noexcept;

} // namespace kasumi::transport::local_detail

#endif
