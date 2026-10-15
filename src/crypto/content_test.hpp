#ifndef KASUMI_CRYPTO_CONTENT_TEST_HPP
#define KASUMI_CRYPTO_CONTENT_TEST_HPP

#include "crypto/content.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace kasumi::crypto::content::test {

#if defined(_WIN32)
struct HandleHashSyscalls {
    decltype(&::SetFilePointerEx) seek = &::SetFilePointerEx;
    decltype(&::ReadFile) read = &::ReadFile;
};

std::expected<Hash, std::string>
hash_file_handle_with_syscalls(void* handle,
                               const HandleHashSyscalls& syscalls);
#endif

} // namespace kasumi::crypto::content::test

#endif
