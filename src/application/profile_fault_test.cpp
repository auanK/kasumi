#include "application/profile_fault_test.hpp"

#ifdef KASUMI_MUTATION_FAULT_TESTS
namespace kasumi::application::fault_test {

thread_local std::function<void(CloneFaultStage)> g_clone_fault_observer =
    nullptr;
thread_local std::function<void(InspectFaultStage)> g_inspect_fault_observer =
    nullptr;
thread_local std::filesystem::path g_inspect_fault_path{};

} // namespace kasumi::application::fault_test
#endif
