#include "application/observation/cache_contract.hpp"

namespace kasumi::application::observation::cache {

const char* describe_result(CacheReuseResult result) noexcept {
    switch (result) {
        case CacheReuseResult::Reusable:
            return "Reusable";
        case CacheReuseResult::InvalidCachedEntry:
            return "InvalidCachedEntry";
        case CacheReuseResult::InvalidCurrentMetadata:
            return "InvalidCurrentMetadata";
        case CacheReuseResult::PathMismatch:
            return "PathMismatch";
        case CacheReuseResult::NotRegularFile:
            return "NotRegularFile";
        case CacheReuseResult::SizeMismatch:
            return "SizeMismatch";
        case CacheReuseResult::MtimeMismatch:
            return "MtimeMismatch";
        case CacheReuseResult::IdentityMismatch:
            return "IdentityMismatch";
        case CacheReuseResult::MissingRequiredIdentity:
            return "MissingRequiredIdentity";
    }
    return "Unknown";
}

CacheReuseResult evaluate_cache_reuse(
    const FileMetadata& /*cached*/,
    const FileMetadata& /*current*/) noexcept {
    // TDD RED Phase: Stub returning failure to verify test harness fails
    return CacheReuseResult::InvalidCurrentMetadata;
}

} // namespace kasumi::application::observation::cache
