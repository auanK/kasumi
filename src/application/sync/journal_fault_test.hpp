#ifndef KASUMI_APPLICATION_SYNC_JOURNAL_FAULT_TEST_HPP
#define KASUMI_APPLICATION_SYNC_JOURNAL_FAULT_TEST_HPP

#include "core/transaction/types.hpp"

#ifdef KASUMI_JOURNAL_FAULT_TESTS
#include <cstdio>
#include <cstdlib>
#include <string>
#endif

namespace kasumi::application::sync::journal_fault_test {

// These hooks exist only in the explicitly opted-in fault-test build.
inline void hit(std::string_view point,
                const transaction::Record* record = nullptr,
                std::size_t index = std::numeric_limits<std::size_t>::max()) {
#ifdef KASUMI_JOURNAL_FAULT_TESTS
    auto name = std::string{point};
    if (index != std::numeric_limits<std::size_t>::max()) {
        name += "/" + std::to_string(index);
    }
    if (std::getenv("KASUMI_TEST_JOURNAL_OBSERVE") != nullptr) {
        std::fprintf(stderr, "KASUMI_TEST_EVENT point=%s\n", name.c_str());
    }
    if (std::getenv("KASUMI_TEST_JOURNAL_OBSERVE") != nullptr && record) {
        std::fprintf(stderr,
                     "KASUMI_TEST_RECORD point=%s phase=%u operations=%zu\n",
                     name.c_str(),
                     static_cast<unsigned>(record->phase),
                     record->progress.size());
        for (std::size_t i = 0; i < record->progress.size(); ++i) {
            std::fprintf(
                stderr,
                "KASUMI_TEST_OP index=%zu action=%zu state=%u original=%u "
                "slot=%u path=%s\n",
                i,
                action_index(record->plan.operations[i].action),
                static_cast<unsigned>(record->progress[i].state),
                static_cast<unsigned>(record->progress[i].had_original),
                record->progress[i].backup_slot,
                record->plan.operations[i].path.generic_string().c_str());
        }
    }
    const auto* crash = std::getenv("KASUMI_TEST_JOURNAL_CRASH");
    if (crash && name == crash) {
        std::fprintf(stderr, "KASUMI_TEST_CRASH point=%s\n", name.c_str());
        std::fflush(stderr);
        std::_Exit(86);
    }
#else
    (void)point;
    (void)record;
    (void)index;
#endif
}

inline bool cleanup_fail(std::string_view point) {
#ifdef KASUMI_JOURNAL_FAULT_TESTS
    const auto* failure = std::getenv("KASUMI_TEST_JOURNAL_FAIL");
    return failure && point == failure;
#else
    (void)point;
    return false;
#endif
}

inline bool fail(std::string_view point, const transaction::Record& record) {
    return record.phase == transaction::Phase::FilesStaged &&
           cleanup_fail(point);
}

} // namespace kasumi::application::sync::journal_fault_test

#endif
