#ifndef KASUMI_APPLICATION_PROFILE_FAULT_TEST_HPP
#define KASUMI_APPLICATION_PROFILE_FAULT_TEST_HPP

#ifdef KASUMI_MUTATION_FAULT_TESTS
#include <cstddef>
#include <filesystem>
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

enum class InspectFaultStage {
    None,
    FailRandomId,
    SimulateTempDirCollision,
    FailSqliteCopy,
    FailCleanup,
    SimulateConcurrentModification,
    FailSnapshot,
    AfterTempDirCreated,
    ConcurrentSnapshotBarrier,
    SnapshotDatabaseCopied,
    SnapshotReady,
    FailMetadataQuery,
    FailLockOpen,
    FailLockAcquire,
    FailCleanupFileRemove,
    FailCleanupDirectoryRemove,
    FailDirectoryIdentity
};

inline thread_local CloneFaultStage g_clone_fault_stage = CloneFaultStage::None;
inline thread_local std::function<void(CloneFaultStage)> g_clone_fault_observer = nullptr;

inline thread_local InspectFaultStage g_inspect_fault_stage = InspectFaultStage::None;
inline thread_local std::function<void(InspectFaultStage)> g_inspect_fault_observer = nullptr;
inline thread_local std::filesystem::path g_inspect_fault_path = {};
inline thread_local bool g_inspect_cleanup_failure_consumed = false;
inline thread_local bool g_inspect_identity_failure_consumed = false;
inline thread_local std::size_t g_inspect_cleanup_attempts = 0;

// Simulates one transient cleanup failure so the owner must retain ownership and
// retry. The old implementation cleared ownership before confirming cleanup.
inline bool inject_cleanup_failure_once(InspectFaultStage stage) {
    if (g_inspect_fault_stage == stage &&
        !g_inspect_cleanup_failure_consumed) {
        g_inspect_cleanup_failure_consumed = true;
        return true;
    }
    return false;
}

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

struct ScopedInspectFaultInjection {
    explicit ScopedInspectFaultInjection(
        InspectFaultStage stage,
        std::function<void(InspectFaultStage)> observer = nullptr,
        std::filesystem::path fault_path = {}) {
        g_inspect_fault_stage = stage;
        g_inspect_fault_observer = std::move(observer);
        g_inspect_fault_path = std::move(fault_path);
        g_inspect_cleanup_failure_consumed = false;
        g_inspect_identity_failure_consumed = false;
        g_inspect_cleanup_attempts = 0;
    }

    ~ScopedInspectFaultInjection() {
        g_inspect_fault_stage = InspectFaultStage::None;
        g_inspect_fault_observer = nullptr;
        g_inspect_fault_path.clear();
        g_inspect_cleanup_failure_consumed = false;
        g_inspect_identity_failure_consumed = false;
        g_inspect_cleanup_attempts = 0;
    }

    ScopedInspectFaultInjection(const ScopedInspectFaultInjection&) = delete;
    ScopedInspectFaultInjection& operator=(const ScopedInspectFaultInjection&) = delete;
};

} // namespace kasumi::application::fault_test
#endif

#endif
