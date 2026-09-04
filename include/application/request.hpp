#ifndef KASUMI_APPLICATION_REQUEST_HPP
#define KASUMI_APPLICATION_REQUEST_HPP

#include <string>

namespace kasumi::application {

// Command types supported by the application engine.
enum class Operation {
    // Bidirectionally synchronizes state between local and remote directories.
    Sync,
    // Simulates synchronization and displays execution plan without modifying
    // data (dry-run).
    Preview,
    // Compares differences between local and remote.
    Status,
    // Analyzes cryptographic and structural integrity of remotely stored blocks.
    Fsck,
    // Quarantines objects unreachable from any logical head.
    GarbageCollect
};

// Request structure defining action to perform and target profile.
struct Request {
    Operation operation = Operation::Sync;
    std::string profile_name;
};

} // namespace kasumi::application

#endif
