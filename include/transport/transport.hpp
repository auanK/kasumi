#ifndef KASUMI_TRANSPORT_TRANSPORT_HPP
#define KASUMI_TRANSPORT_TRANSPORT_HPP

#include "transport/types.hpp"

#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::transport {

// Function signature for implementation initialization.
using InitializeFunction = Result (*)(void* context);

// Function signature for uploading an object.
using PutFunction = Result (*)(void* context,
                               const std::filesystem::path& source,
                               std::string_view identifier);

// Function signature for downloading an object.
using GetFunction = Result (*)(void* context,
                               std::string_view identifier,
                               const std::filesystem::path& destination);

// Batch of objects for optimized download. Identifiers are relative to
// the remote prefix and local destination directory.
struct GetBatch {
    std::string source_prefix;
    std::filesystem::path destination_root;
    std::vector<std::string> identifiers;
    std::size_t max_parallel_transfers = 0;
};

// Function signature for downloading a batch of objects.
using GetBatchFunction = Result (*)(void* context, const GetBatch& batch);

// Batch of objects for optimized upload.
struct PutBatch {
    std::filesystem::path source_root;
    std::vector<std::string> identifiers;
    std::size_t max_parallel_transfers = 0;
};

// Function signature for uploading a batch of objects.
using PutBatchFunction = Result (*)(void* context, const PutBatch& batch);

// Function signature for querying object existence.
using PresenceFunction = PresenceResult (*)(void* context,
                                            std::string_view identifier);

// Function signature for full storage listing.
using ListFunction = ListingResult (*)(void* context);

// Function signature for direct listing under a validated relative prefix.
using ListPrefixFunction = ListingResult (*)(void* context,
                                             std::string_view prefix);

// Function signature for optional physical hash query.
using PhysicalHashFunction = std::expected<std::string, Error> (*)(
    void* context, std::string_view identifier, std::string_view algorithm);

// Expected physical hash for an object.
struct PhysicalHashExpectation {
    std::string identifier;
    std::string expected_hash;
};

// Batch physical hash verification request.
struct PhysicalHashBatchRequest {
    std::filesystem::path scratch_root;
    std::vector<PhysicalHashExpectation> objects;
    std::string algorithm;
};

// Batch physical hash verification result.
struct PhysicalHashBatchReport {
    std::vector<std::string> mismatched;
    std::vector<std::string> missing;
    std::vector<std::string> errors;
};

using PhysicalHashBatchResult = std::expected<PhysicalHashBatchReport, Error>;

// Optional function signature for native batch physical hash verification.
using PhysicalHashBatchFunction = PhysicalHashBatchResult (*)(
    void* context, const PhysicalHashBatchRequest& request);

// Control-plane reads executed in a single envelope. All listings
// must complete before any presence check begins.
struct ControlReadBatchRequest {
    std::vector<std::string> list_prefixes;
    std::vector<std::string> presence_identifiers;
};

struct ControlReadBatchResult {
    std::vector<std::vector<std::string>> listings;
    std::vector<Presence> presences;
};

using ControlReadBatchResponse = std::expected<ControlReadBatchResult, Error>;
using ControlReadBatchFunction = ControlReadBatchResponse (*)(
    void* context, const ControlReadBatchRequest& request);

// Function signature for idempotent object removal.
using RemoveFunction = RemovalResult (*)(void* context,
                                         std::string_view identifier);

// Operations table; prefix listing and physical hash are optional.
struct StorageOperations {
    InitializeFunction initialize = nullptr;
    PutFunction put = nullptr;
    PutBatchFunction put_batch = nullptr;
    GetFunction get = nullptr;
    GetBatchFunction get_batch = nullptr;
    PresenceFunction presence = nullptr;
    ListFunction list = nullptr;
    ListPrefixFunction list_prefix = nullptr;
    PhysicalHashFunction physical_hash = nullptr;
    PhysicalHashBatchFunction physical_hash_batch = nullptr;
    ControlReadBatchFunction control_read_batch = nullptr;
    RemoveFunction remove = nullptr;
    std::size_t physical_hash_batch_min_objects = 0;
};

// Function signature for releasing implementation state.
using DestroyTransportStateFunction = void (*)(void* state) noexcept;

// Owning handle for implementation state.
using TransportStateHandle =
    std::unique_ptr<void, DestroyTransportStateFunction>;

// Opened transport containing state and operations table.
struct Transport {
    TransportStateHandle state{nullptr, nullptr};
    StorageOperations storage;
};

// Validates only the storage location syntax.
Result validate_transport_location(std::string_view location);

// Opens the implementation indicated by location.
std::expected<Transport, Error>
open_transport(std::string_view location,
               const std::filesystem::path& forbidden_executable_root = {});

// Confirms that state and mandatory operations are available.
bool valid(const Transport& transport) noexcept;

// Initializes the opened storage.
Result initialize(Transport& transport);

// Uploads the local file to the given identifier.
Result put(Transport& transport,
           const std::filesystem::path& source,
           std::string_view identifier);

// Uploads a batch of local files. Falls back to individual put() calls if
// unsupported natively by backend.
Result put_batch(Transport& transport, const PutBatch& batch);

// Downloads the object to the destination path.
Result get(Transport& transport,
           std::string_view identifier,
           const std::filesystem::path& destination);

// Downloads a batch of objects. Falls back to individual get() calls if
// unsupported natively by backend.
Result get_batch(Transport& transport, const GetBatch& batch);

// Queries whether an object exists.
PresenceResult presence(Transport& transport, std::string_view identifier);

// Lists all identifiers in storage.
ListingResult list(Transport& transport);

// Lists names directly under a validated relative prefix.
ListingResult list(Transport& transport, std::string_view prefix);

// Queries physical hash, when available.
std::expected<std::string, Error> physical_hash(Transport& transport,
                                                std::string_view identifier,
                                                std::string_view algorithm);

// Queries physical hashes for multiple objects when supported natively by
// the backend.
PhysicalHashBatchResult
physical_hash_batch(Transport& transport,
                    const PhysicalHashBatchRequest& request);

// Reports whether backend prefers native batch verification for this count.
bool prefers_physical_hash_batch(const Transport& transport,
                                 std::size_t object_count) noexcept;

// Executes ordered control reads within an optional single envelope.
ControlReadBatchResponse
control_read_batch(Transport& transport,
                   const ControlReadBatchRequest& request);

// Removes the object idempotently.
RemovalResult remove(Transport& transport, std::string_view identifier);

} // namespace kasumi::transport

#endif
