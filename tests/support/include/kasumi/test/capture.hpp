#ifndef KASUMI_TEST_CAPTURE_HPP
#define KASUMI_TEST_CAPTURE_HPP

#include <gtest/gtest.h>
#include <string>
#include <utility>

namespace kasumi::test {

template <typename Fn> std::string capture_stdout(Fn&& fn) {
    testing::internal::CaptureStdout();
    std::forward<Fn>(fn)();
    return testing::internal::GetCapturedStdout();
}

} // namespace kasumi::test

#endif
