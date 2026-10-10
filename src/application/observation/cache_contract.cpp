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
    const FileMetadata& cached,
    const FileMetadata& current) noexcept {
    if (!cached.is_valid) {
        return CacheReuseResult::InvalidCachedEntry;
    }
    if (!current.is_valid) {
        return CacheReuseResult::InvalidCurrentMetadata;
    }
    if (cached.path.empty() || current.path.empty() || cached.path != current.path) {
        return CacheReuseResult::PathMismatch;
    }
    if (cached.kind != EntryKind::RegularFile || current.kind != EntryKind::RegularFile) {
        return CacheReuseResult::NotRegularFile;
    }
    if (cached.size != current.size) {
        return CacheReuseResult::SizeMismatch;
    }
    if (cached.mtime_nanoseconds != current.mtime_nanoseconds) {
        return CacheReuseResult::MtimeMismatch;
    }
    if (!cached.identity.has_value() || !current.identity.has_value()) {
        return CacheReuseResult::MissingRequiredIdentity;
    }
    if (*cached.identity != *current.identity) {
        return CacheReuseResult::IdentityMismatch;
    }

    return CacheReuseResult::Reusable;
}

} // namespace kasumi::application::observation::cache
