#ifndef KASUMI_APPLICATION_PROFILE_FAULT_TEST_HPP
#define KASUMI_APPLICATION_PROFILE_FAULT_TEST_HPP

#ifdef KASUMI_MUTATION_FAULT_TESTS
#include <functional>
#include <utility>

namespace kasumi::application::fault_test {

enum class CloneFaultStage {
    None,
    FailKeyWrite,
    FailDatabaseInit,
    FailConfigSave,
    FailRollbackRemove
};

inline thread_local CloneFaultStage g_clone_fault_stage = CloneFaultStage::None;
inline thread_local std::function<void(CloneFaultStage)> g_clone_fault_observer = nullptr;

struct ScopedCloneFaultInjection {
    explicit ScopedCloneFaultInjection(
        CloneFaultStage stage,
        std::function<void(CloneFaultStage)> observer = nullptr) {
        g_clone_fault_stage = stage;
        g_clone_fault_observer = std::move(observer);
    }

    ~ScopedCloneFaultInjection() {
        g_clone_fault_stage = CloneFaultStage::None;
        g_clone_fault_observer = nullptr;
    }

    ScopedCloneFaultInjection(const ScopedCloneFaultInjection&) = delete;
    ScopedCloneFaultInjection& operator=(const ScopedCloneFaultInjection&) = delete;
};

} // namespace kasumi::application::fault_test
#endif

#endif
