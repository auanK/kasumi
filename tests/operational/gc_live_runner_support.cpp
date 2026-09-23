#include "gc_live_runner_support.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <set>
#include <system_error>
#include <utility>

namespace kasumi::operational::gc_live_runner {

namespace {

constexpr std::string_view default_owner_identifier = "owner.marker";

[[maybe_unused]] std::string read_file_string(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string{std::istreambuf_iterator<char>{stream}, {}};
}

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::vector<std::uint8_t>{std::istreambuf_iterator<char>{stream}, {}};
}

bool write_file_string(const std::filesystem::path& path, std::string_view text) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    return static_cast<bool>(stream);
}

struct VaultTransportContext {
    transport::Transport* underlying = nullptr;
    std::string hidden_marker = "owner.marker";
};

void destroy_vault_context(void* context) noexcept {
    delete static_cast<VaultTransportContext*>(context);
}

transport::ListingResult vault_list(void* context) {
    auto* ctx = static_cast<VaultTransportContext*>(context);
    auto raw = ctx->underlying->storage.list(ctx->underlying->state.get());
    if (!raw) {
        return raw;
    }
    std::vector<std::string> filtered;
    filtered.reserve(raw->size());
    for (const auto& id : *raw) {
        if (id != ctx->hidden_marker) {
            filtered.push_back(id);
        }
    }
    return filtered;
}

transport::ListingResult vault_list_prefix(void* context, std::string_view prefix) {
    auto* ctx = static_cast<VaultTransportContext*>(context);
    if (!ctx->underlying->storage.list_prefix) {
        return std::unexpected(transport::Error{
            .code = transport::ErrorCode::Unsupported,
            .message = "prefix listing unsupported",
        });
    }
    auto raw = ctx->underlying->storage.list_prefix(ctx->underlying->state.get(), prefix);
    if (!raw) {
        return raw;
    }
    std::vector<std::string> filtered;
    filtered.reserve(raw->size());
    for (const auto& id : *raw) {
        if (id != ctx->hidden_marker) {
            filtered.push_back(id);
        }
    }
    return filtered;
}

transport::PresenceResult vault_presence(void* context, std::string_view identifier) {
    auto* ctx = static_cast<VaultTransportContext*>(context);
    if (identifier == ctx->hidden_marker) {
        return transport::Presence::Absent;
    }
    return ctx->underlying->storage.presence(ctx->underlying->state.get(), identifier);
}

transport::RemovalResult vault_remove(void* context, std::string_view identifier) {
    auto* ctx = static_cast<VaultTransportContext*>(context);
    if (identifier == ctx->hidden_marker) {
        return transport::Removal::AlreadyAbsent;
    }
    return ctx->underlying->storage.remove(ctx->underlying->state.get(), identifier);
}

transport::Result vault_put(void* context,
                            const std::filesystem::path& source,
                            std::string_view identifier) {
    auto* ctx = static_cast<VaultTransportContext*>(context);
    return ctx->underlying->storage.put(ctx->underlying->state.get(), source, identifier);
}

transport::Result vault_get(void* context,
                            std::string_view identifier,
                            const std::filesystem::path& destination) {
    auto* ctx = static_cast<VaultTransportContext*>(context);
    return ctx->underlying->storage.get(ctx->underlying->state.get(), identifier, destination);
}

transport::Result vault_copy(void* context,
                             std::string_view source_identifier,
                             std::string_view destination_identifier) {
    auto* ctx = static_cast<VaultTransportContext*>(context);
    if (!ctx->underlying->storage.copy) {
        return std::unexpected(transport::Error{
            .code = transport::ErrorCode::Unsupported,
            .message = "native copy unsupported",
        });
    }
    return ctx->underlying->storage.copy(ctx->underlying->state.get(),
                                         source_identifier,
                                         destination_identifier);
}

std::expected<std::string, transport::Error>
vault_physical_hash(void* context,
                    std::string_view identifier,
                    std::string_view algorithm) {
    auto* ctx = static_cast<VaultTransportContext*>(context);
    if (!ctx->underlying->storage.physical_hash) {
        return std::unexpected(transport::Error{
            .code = transport::ErrorCode::Unsupported,
            .message = "physical hash unsupported",
        });
    }
    return ctx->underlying->storage.physical_hash(ctx->underlying->state.get(),
                                                  identifier,
                                                  algorithm);
}

} // namespace

std::string_view stage_name(LiveGcStage stage) noexcept {
    switch (stage) {
        case LiveGcStage::Start:
            return "START";
        case LiveGcStage::PreflightPassed:
            return "PREFLIGHT_PASSED";
        case LiveGcStage::ChildInitialized:
            return "CHILD_INITIALIZED";
        case LiveGcStage::OwnershipEstablished:
            return "OWNERSHIP_ESTABLISHED";
        case LiveGcStage::ScenarioPublished:
            return "SCENARIO_PUBLISHED";
        case LiveGcStage::PreInventoryVerified:
            return "PRE_INVENTORY_VERIFIED";
        case LiveGcStage::GcAttempted:
            return "GC_ATTEMPTED";
        case LiveGcStage::PostInventoryVerified:
            return "POST_INVENTORY_VERIFIED";
        case LiveGcStage::CleanupCompleted:
            return "CLEANUP_COMPLETED";
    }
    return "UNKNOWN";
}

bool is_authorized_live_parent(std::string_view remote_parent) noexcept {
    return remote_parent == "kasumi:integration-tests";
}

transport::Transport make_vault_transport(transport::Transport& underlying,
                                          std::string hidden_marker) {
    auto* ctx = new VaultTransportContext{
        .underlying = &underlying,
        .hidden_marker = std::move(hidden_marker),
    };
    transport::StorageOperations ops = underlying.storage;
    ops.list = vault_list;
    if (ops.list_prefix) {
        ops.list_prefix = vault_list_prefix;
    }
    ops.presence = vault_presence;
    ops.remove = vault_remove;
    ops.put = vault_put;
    ops.get = vault_get;
    if (ops.copy) {
        ops.copy = vault_copy;
    }
    if (ops.physical_hash) {
        ops.physical_hash = vault_physical_hash;
    }
    return transport::Transport{
        .state = transport::TransportStateHandle{ctx, destroy_vault_context},
        .storage = ops,
    };
}

std::expected<ScenarioObjects, transport::Error>
setup_scenario(transport::Transport& vault_storage,
               const std::filesystem::path& scratch_root,
               std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key) {
    ScenarioObjects result;
    std::copy(key.begin(), key.end(), result.key.begin());

    const auto scenario_dir = scratch_root / "scenario";
    std::error_code fs_error;
    std::filesystem::create_directories(scenario_dir, fs_error);
    if (fs_error) {
        return std::unexpected(transport::Error{
            .code = transport::ErrorCode::Io,
            .message = "could not create local scenario scratch directory",
        });
    }

    const auto layout = kasumi::application::history_storage::derive_remote_layout(key);

    // 1. Reachable content
    constexpr std::string_view reachable_text = "kasumi live gc reachable content v1";
    const auto reachable_plain = scenario_dir / "reachable.plain";
    const auto reachable_enc = scenario_dir / "reachable.enc";
    if (!write_file_string(reachable_plain, reachable_text)) {
        return std::unexpected(transport::Error{.code = transport::ErrorCode::Io, .message = "failed to write reachable plain"});
    }
    if (!kasumi::crypto::encrypt_file(reachable_plain, reachable_enc, key, kasumi::crypto::FilePurpose::Content)) {
        return std::unexpected(transport::Error{.code = transport::ErrorCode::Io, .message = "failed to encrypt reachable content"});
    }
    result.reachable_content_id = kasumi::crypto::content_identifier(key, kasumi::hasher::hash_string(reachable_text));
    auto put_reachable = transport::put(vault_storage, reachable_enc, result.reachable_content_id);
    if (!put_reachable) {
        return std::unexpected(put_reachable.error());
    }

    // 2. Reachable commit referencing reachable content
    kasumi::Snapshot tree{
        .rows = {
            kasumi::NodeRow{.path = "", .hash = {}, .size = 0, .mtime = {}, .is_directory = true},
            kasumi::NodeRow{.path = "live.txt", .hash = kasumi::hasher::hash_string(reachable_text), .size = reachable_text.size(), .mtime = {}, .is_directory = false},
        },
    };
    kasumi::finalize_snapshot(tree);
    auto commit_res = kasumi::history::make_commit(0, {}, tree);
    if (!commit_res) {
        return std::unexpected(transport::Error{.code = transport::ErrorCode::Io, .message = "failed to create commit"});
    }
    auto published = kasumi::application::history_storage::publish_commit(vault_storage, key, *commit_res, scratch_root);
    if (!published) {
        return std::unexpected(transport::Error{.code = transport::ErrorCode::Io, .message = published.error().detail});
    }
    result.reachable_commit_id = kasumi::application::history_storage::commit_object(layout, published->head);
    result.reachable_marker_id = kasumi::application::history_storage::marker_object(layout, published->head);

    // 3. Orphan candidate
    constexpr std::string_view orphan_text = "kasumi live gc orphan candidate v1";
    const auto orphan_plain = scenario_dir / "orphan.plain";
    const auto orphan_enc = scenario_dir / "orphan.enc";
    if (!write_file_string(orphan_plain, orphan_text)) {
        return std::unexpected(transport::Error{.code = transport::ErrorCode::Io, .message = "failed to write orphan plain"});
    }
    auto enc_res = kasumi::crypto::encrypt_file_with_hashes(orphan_plain, orphan_enc, key, kasumi::crypto::FilePurpose::Content);
    if (!enc_res) {
        return std::unexpected(transport::Error{.code = transport::ErrorCode::Io, .message = "failed to encrypt orphan candidate"});
    }
    result.candidate_id = kasumi::crypto::content_identifier(key, kasumi::hasher::hash_string(orphan_text));
    result.candidate_sha256 = enc_res->ciphertext_sha256;

    auto put_orphan = transport::put(vault_storage, orphan_enc, result.candidate_id);
    if (!put_orphan) {
        return std::unexpected(put_orphan.error());
    }

    // 4. Expected quarantine identifiers
    auto q_id = kasumi::application::history_storage::maintenance_protocol::quarantine_identifier(layout, result.candidate_id);
    if (!q_id) {
        return std::unexpected(transport::Error{.code = transport::ErrorCode::InvalidIdentifier, .message = "failed to compute quarantine identifier"});
    }
    result.expected_quarantine_id = *q_id;
    result.expected_quarantine_meta_id = *q_id + ".meta";

    result.expected_pre_vault_objects = {
        result.reachable_content_id,
        result.reachable_commit_id,
        result.reachable_marker_id,
        result.candidate_id,
    };
    std::ranges::sort(result.expected_pre_vault_objects);

    result.expected_post_vault_objects = {
        result.reachable_content_id,
        result.reachable_commit_id,
        result.reachable_marker_id,
        result.expected_quarantine_id,
        result.expected_quarantine_meta_id,
    };
    std::ranges::sort(result.expected_post_vault_objects);

    return result;
}

std::expected<StorageInventory, transport::Error>
capture_inventory(transport::Transport& child_storage,
                  const std::filesystem::path& scratch_root,
                  bool capture_exact_bytes) {
    auto listing = transport::list(child_storage);
    if (!listing) {
        return std::unexpected(listing.error());
    }

    StorageInventory inventory;
    std::size_t download_seq = 0;
    const auto dl_dir = scratch_root / "inv_dl";
    std::filesystem::create_directories(dl_dir);

    for (const auto& id : *listing) {
        if (id == default_owner_identifier) {
            inventory.owner_marker = std::string{id};
            continue;
        }

        InventoryEntry entry;
        entry.identifier = id;

        auto hash = transport::physical_hash(child_storage, id, "sha256");
        if (hash) {
            entry.physical_sha256 = *hash;
        }

        if (capture_exact_bytes) {
            const auto dl_path = dl_dir / ("obj-" + std::to_string(download_seq++));
            auto dl = transport::get(child_storage, id, dl_path);
            if (dl) {
                entry.exact_bytes = read_file_bytes(dl_path);
                entry.size = entry.exact_bytes->size();
                std::error_code ec;
                std::filesystem::remove(dl_path, ec);
            }
        }
        inventory.vault_objects.push_back(std::move(entry));
    }

    std::ranges::sort(inventory.vault_objects, {}, &InventoryEntry::identifier);
    return inventory;
}

RunnerReport run(
    const RunnerOptions& options,
    transport::Transport* parent_transport_override,
    transport::Transport* child_transport_override,
    GcInvocation gc_override) {
    RunnerReport report;
    report.remote_parent = options.remote_parent;
    report.stage_reached = LiveGcStage::Start;

    // Gate 1: Check authorization flag
    if (!options.execute_live_gc) {
        report.status = "REFUSED";
        report.error_message = "dry run safety: --execute-live-gc required";
        return report;
    }

    // Gate 2: Check remote parent authorization (strict for live runs)
    if (!parent_transport_override && !is_authorized_live_parent(options.remote_parent)) {
        report.status = "REFUSED";
        report.error_message = "remote parent not authorized for live GC";
        return report;
    }

    const auto parsed_parent = smoke::parse_remote_parent(options.remote_parent);
    if (!parsed_parent) {
        report.status = "REFUSED";
        report.error_message = "invalid remote parent format";
        return report;
    }

    // Child generation
    std::string child_name;
    if (options.explicit_child) {
        child_name = *options.explicit_child;
    } else {
        const auto nonce = kasumi::platform::random::hex_id();
        if (!nonce) {
            report.status = "FAILED";
            report.error_message = "could not generate random nonce";
            return report;
        }
        auto generated = preflight::child_namespace(*nonce);
        if (!generated) {
            report.status = "FAILED";
            report.error_message = generated.error();
            return report;
        }
        child_name = *generated;
    }

    const auto location = preflight::child_location(*parsed_parent, child_name);
    if (!location) {
        report.status = "REFUSED";
        report.error_message = location.error();
        return report;
    }
    report.effective_namespace = *location;

    // Transport acquisition
    std::optional<transport::Transport> owned_parent_storage;
    transport::Transport* parent_storage = parent_transport_override;
    if (!parent_storage) {
        auto opened = transport::open_transport(parsed_parent->location);
        if (!opened) {
            report.status = "REFUSED";
            report.error_message = "could not open parent transport: " + transport::describe(opened.error());
            return report;
        }
        owned_parent_storage = std::move(*opened);
        parent_storage = &*owned_parent_storage;
    }

    // Phase 5B / 5C Preflight Gate
    preflight::PreInitializeObservation pre_obs;
    if (!parent_transport_override) {
        // Real live preflight probe
        pre_obs = preflight::observe_pre_initialize(
            *parent_storage, *parsed_parent, child_name, options.preflight_timeout);
        auto classification = preflight::classify_pre_initialize(
            pre_obs, *parsed_parent, child_name);
        report.pre_initialize = preflight::to_json(pre_obs, classification);

        if (classification.disposition != preflight::ChildDisposition::Unused) {
            report.status = classification.disposition == preflight::ChildDisposition::Existing
                                ? "EXISTING"
                                : "REFUSED";
            report.error_message = classification.reason;
            return report;
        }
    } else {
        // Fake / test environment preflight check
        if (child_transport_override) {
            auto listing = transport::list(*child_transport_override);
            if (listing && !listing->empty()) {
                report.status = "REFUSED";
                report.error_message = "pre-existing child detected in test harness";
                return report;
            }
        }
        pre_obs = preflight::PreInitializeObservation{
            .transport = {
                .result = "FAILED",
                .error_category = transport::ErrorCode::StorageNotFound,
            },
            .raw_rc = {
                .endpoint = "operations/list",
                .request_fs = parsed_parent->remote_name + ":",
                .request_remote = parsed_parent->directory.empty() ? child_name : (parsed_parent->directory + "/" + child_name),
                .result = "FAILED",
                .native_status = 404,
                .error_category = transport::ErrorCode::ProtocolFailure,
                .error_message = "error in ListJSON: directory not found",
            },
        };
        auto classification = preflight::classify_pre_initialize(pre_obs, *parsed_parent, child_name);
        report.pre_initialize = preflight::to_json(pre_obs, classification);
    }
    report.stage_reached = LiveGcStage::PreflightPassed;

    // Generate random owner token BEFORE any initialize / storage mutation
    // Must fail closed on RNG failure with zero static fallback
    std::string owner_token;
    if (options.explicit_owner_token) {
        owner_token = *options.explicit_owner_token;
    } else {
        std::optional<std::string> rnd;
        if (options.random_generator) {
            rnd = (*options.random_generator)();
        } else {
            auto hex = kasumi::platform::random::hex_id();
            if (hex) {
                rnd = *hex;
            }
        }
        if (!rnd || rnd->empty()) {
            report.status = "FAILED";
            report.error_message = "failed to generate random owner token";
            return report;
        }
        owner_token = "token-" + *rnd;
    }

    // Open child storage
    std::optional<preflight::ChildStorage> owned_child_storage;
    preflight::ChildStorage* child_storage_ptr = nullptr;
    preflight::ChildStorage synthetic_child_storage;
    if (child_transport_override) {
        synthetic_child_storage = preflight::ChildStorage{
            .parent = *parsed_parent,
            .child = child_name,
            .storage = std::move(*child_transport_override),
        };
        child_storage_ptr = &synthetic_child_storage;
    } else {
        auto opened = preflight::open_child_storage(*parsed_parent, child_name);
        if (!opened) {
            report.status = "FAILED";
            report.error_message = "could not open child storage: " + transport::describe(opened.error());
            return report;
        }
        owned_child_storage = std::move(*opened);
        child_storage_ptr = &*owned_child_storage;
    }
    auto& child_storage = *child_storage_ptr;

    // Initialize child using Phase 5B gate
    auto init_result = preflight::initialize_child(child_storage, pre_obs);
    if (!init_result) {
        report.status = "FAILED";
        report.error_message = "child initialize failed: " + transport::describe(init_result.error());
        return report;
    }

    // Post-initialize observation using Phase 5B gate
    auto post_obs = preflight::observe_post_initialize(child_storage);
    auto post_disposition = preflight::classify_post_initialize(post_obs);
    report.post_initialize = preflight::to_json(post_obs, post_disposition);
    if (post_disposition != preflight::PostInitializeDisposition::Empty) {
        report.status = "REFUSED";
        report.stage_reached = LiveGcStage::ChildInitialized;
        report.error_message = "post-initialize listing was non-empty";
        return report;
    }
    report.stage_reached = LiveGcStage::ChildInitialized;

    const auto marker_src = options.local_scratch / "owner_marker.src";
    const auto marker_readback = options.local_scratch / "owner_marker.readback";
    std::error_code ec;
    std::filesystem::remove(marker_src, ec);
    std::filesystem::remove(marker_readback, ec);

    if (!write_file_string(marker_src, owner_token)) {
        report.status = "FAILED";
        report.error_message = "failed to write local owner marker source";
        return report;
    }

    // Establish ownership marker using Phase 5B gate
    auto marker_res = preflight::establish_ownership_marker(
        child_storage,
        post_obs,
        owner_token,
        marker_src,
        marker_readback);

    if (!marker_res) {
        report.status = "FAILED";
        report.ownership.result = "FAILED";
        auto pres = transport::presence(child_storage.storage, default_owner_identifier);
        report.ownership.marker_written = (pres && *pres == transport::Presence::Present);
        report.ownership.marker_readback_verified = false;
        report.error_message = "failed to establish owner marker: " + transport::describe(marker_res.error());
        return report;
    }
    report.ownership.result = "SUCCESS";
    report.ownership.marker_written = true;
    report.ownership.marker_readback_verified = true;
    report.stage_reached = LiveGcStage::OwnershipEstablished;

    // Create vault transport view (filters out owner.marker)
    auto vault_transport = make_vault_transport(child_storage.storage, std::string{default_owner_identifier});

    // Synthetic key
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    if (options.explicit_key) {
        key = *options.explicit_key;
    } else {
        for (std::size_t i = 0; i < key.size(); ++i) {
            key[i] = static_cast<std::uint8_t>(i + 1);
        }
    }

    // Publish scenario
    auto scenario = setup_scenario(vault_transport, options.local_scratch, key);
    if (!scenario) {
        report.status = "FAILED";
        report.error_message = "failed to publish scenario: " + scenario.error().message;
        if (options.preserve_evidence_on_failure) {
            report.cleanup.result = "preserved";
            report.cleanup.detail = "evidence preserved on scenario failure";
        }
        return report;
    }
    report.scenario.reachable_identifier = scenario->reachable_content_id;
    report.scenario.candidate_identifier = scenario->candidate_id;
    report.scenario.candidate_sha256 = scenario->candidate_sha256;
    report.scenario.quarantine_identifier = scenario->expected_quarantine_id;
    report.stage_reached = LiveGcStage::ScenarioPublished;

    // Capture pre-GC inventory
    auto inv_before = capture_inventory(child_storage.storage, options.local_scratch, true);
    if (!inv_before) {
        report.status = "FAILED";
        report.error_message = "failed to capture pre-GC inventory: " + transport::describe(inv_before.error());
        if (options.preserve_evidence_on_failure) {
            report.cleanup.result = "preserved";
            report.cleanup.detail = "evidence preserved on pre-GC inventory capture failure";
        }
        return report;
    }
    report.inventory_before = std::move(*inv_before);

    // Verify pre-GC inventory
    bool pre_inventory_matches =
        report.inventory_before.owner_marker.has_value() &&
        report.inventory_before.vault_objects.size() == scenario->expected_pre_vault_objects.size();
    if (pre_inventory_matches) {
        for (std::size_t i = 0; i < scenario->expected_pre_vault_objects.size(); ++i) {
            if (report.inventory_before.vault_objects[i].identifier != scenario->expected_pre_vault_objects[i]) {
                pre_inventory_matches = false;
                break;
            }
        }
    }
    if (!pre_inventory_matches) {
        report.status = "FAILED";
        report.error_message = "pre-GC inventory does not match expected scenario objects";
        if (options.preserve_evidence_on_failure) {
            report.cleanup.result = "preserved";
            report.cleanup.detail = "evidence preserved on pre-GC inventory mismatch";
        }
        return report;
    }
    report.stage_reached = LiveGcStage::PreInventoryVerified;

    // Build runtime data
    const auto local_dir = options.local_scratch / "local";
    const auto profile_dir = options.local_scratch / "profile";
    std::filesystem::create_directories(local_dir);
    std::filesystem::create_directories(profile_dir);
    kasumi::runtime::RuntimeData runtime_data{
        .local_dir = local_dir,
        .database_path = profile_dir / "db.sqlite",
        .key_path = profile_dir / "key.bin",
        .storage_location = "unused",
    };

    // Execute GC (exactly once)
    report.stage_reached = LiveGcStage::GcAttempted;
    report.gc.called = true;
    report.gc.call_count = 1U;

    std::expected<integrity::GarbageCollectResult, integrity::Error> gc_result;
    if (gc_override) {
        gc_result = gc_override(runtime_data, vault_transport, key);
    } else {
        gc_result = kasumi::application::integrity::garbage_collect(runtime_data, vault_transport, key);
    }

    // Capture metrics
    report.metrics.verified_copy_source_physical_hash = kasumi::platform::perf_trace::get_count("verified copy source physical hash");
    report.metrics.verified_copy_native_copy = kasumi::platform::perf_trace::get_count("verified copy native copy");
    report.metrics.verified_copy_native_copy_successes = kasumi::platform::perf_trace::get_count("verified copy native copy successes");
    report.metrics.verified_copy_destination_physical_hash = kasumi::platform::perf_trace::get_count("verified copy destination physical hash");
    report.metrics.verified_copy_native_copy_verifications = kasumi::platform::perf_trace::get_count("verified copy native copy verifications");
    report.metrics.gc_candidate_verified_copy = kasumi::platform::perf_trace::get_count("gc candidate verified copy");
    report.metrics.gc_candidate_metadata_publish = kasumi::platform::perf_trace::get_count("gc candidate metadata publish");
    report.metrics.gc_candidate_pre_remove_barrier_verification = kasumi::platform::perf_trace::get_count("gc candidate pre-remove barrier verification");
    report.metrics.gc_candidate_remove = kasumi::platform::perf_trace::get_count("gc candidate remove");

    if (!gc_result) {
        report.gc.result = "FAILED";
        report.gc.error_category = transport::ErrorCode::Io;
        report.gc.error_detail_sanitized = gc_result.error().detail;
        report.status = "FAILED";

        auto inv_fail = capture_inventory(child_storage.storage, options.local_scratch, true);
        if (inv_fail) {
            report.inventory_after = std::move(*inv_fail);
        }

        if (options.preserve_evidence_on_failure) {
            report.cleanup.result = "preserved";
            report.cleanup.detail = "evidence preserved on GC failure";
            return report;
        }

        // Attempt safe cleanup of owned objects if ownership still verifiable
        std::vector<std::string> cleanup_targets = {
            scenario->reachable_content_id,
            scenario->reachable_commit_id,
            scenario->reachable_marker_id,
            scenario->candidate_id,
        };
        report.cleanup = preflight::cleanup_owned_child(child_storage, owner_token, cleanup_targets, options.local_scratch);
        return report;
    }

    report.gc.result = "SUCCESS";
    report.gc.candidate_objects = gc_result->candidate_objects;
    report.gc.quarantined_objects = gc_result->quarantined_objects;
    report.gc.restored_objects = gc_result->restored_objects;
    report.gc.purged_objects = gc_result->purged_objects;

    // Capture post-GC inventory
    auto inv_after = capture_inventory(child_storage.storage, options.local_scratch, true);
    if (!inv_after) {
        report.status = "FAILED";
        report.error_message = "failed to capture post-GC inventory";
        return report;
    }
    report.inventory_after = std::move(*inv_after);

    // Post-GC Invariant Verification (Passo 9)
    std::set<std::string> post_ids;
    for (const auto& item : report.inventory_after.vault_objects) {
        post_ids.insert(item.identifier);
    }

    report.validation.reachable_preserved =
        post_ids.contains(scenario->reachable_content_id) &&
        post_ids.contains(scenario->reachable_commit_id) &&
        post_ids.contains(scenario->reachable_marker_id);

    report.validation.source_removed = !post_ids.contains(scenario->candidate_id);
    report.validation.quarantine_present = post_ids.contains(scenario->expected_quarantine_id);

    // Verify quarantine hash matches source
    if (report.validation.quarantine_present) {
        auto q_it = std::ranges::find_if(report.inventory_after.vault_objects, [&](const auto& item) {
            return item.identifier == scenario->expected_quarantine_id;
        });
        if (q_it != report.inventory_after.vault_objects.end()) {
            report.validation.quarantine_verified = (q_it->physical_sha256 == scenario->candidate_sha256);
        }
    }

    // Verify quarantine metadata authentication
    auto q_inventory = kasumi::application::history_storage::maintenance_protocol::inventory_quarantine(
        vault_transport, key, options.local_scratch);
    if (q_inventory && q_inventory->size() == 1) {
        auto verified_meta = kasumi::application::history_storage::maintenance_protocol::verify_quarantine(
            vault_transport, q_inventory->front(), options.local_scratch);
        report.validation.metadata_authenticated = verified_meta.has_value() && *verified_meta;
    }

    for (const auto& expected : scenario->expected_post_vault_objects) {
        if (!post_ids.contains(expected)) {
            report.validation.unexpected_removed++;
        }
    }
    for (const auto& actual : post_ids) {
        if (!std::ranges::binary_search(scenario->expected_post_vault_objects, actual)) {
            report.validation.unexpected_created++;
        }
    }

    bool all_validations_pass =
        report.validation.reachable_preserved &&
        report.validation.source_removed &&
        report.validation.quarantine_present &&
        report.validation.quarantine_verified &&
        report.validation.metadata_authenticated &&
        report.validation.unexpected_removed == 0 &&
        report.inventory_after.owner_marker.has_value();

    if (!all_validations_pass) {
        report.status = "FAILED";
        report.error_message = "post-GC invariants violated";
        if (options.preserve_evidence_on_failure) {
            report.cleanup.result = "preserved";
            report.cleanup.detail = "evidence preserved on invariant failure";
        }
        return report;
    }
    report.stage_reached = LiveGcStage::PostInventoryVerified;

    // Pre-cleanup Audit (Passo 7 & 8):
    // Invariant: While any un-enumerated object or residue exists in child storage,
    // owner.marker MUST NOT be removed!
    std::set<std::string> allowed_cleanup_ids{
        scenario->reachable_content_id,
        scenario->reachable_commit_id,
        scenario->reachable_marker_id,
        scenario->expected_quarantine_id,
        scenario->expected_quarantine_meta_id,
    };
    bool unallowed_residue_detected = false;
    for (const auto& item : report.inventory_after.vault_objects) {
        if (!allowed_cleanup_ids.contains(item.identifier)) {
            unallowed_residue_detected = true;
            break;
        }
    }
    if (unallowed_residue_detected) {
        report.status = "FAILED";
        report.error_message = "unexpected residue in child namespace prevents safe cleanup; owner marker retained";
        report.cleanup.result = "refused";
        report.cleanup.detail = "unknown residue in child namespace retains owner marker";
        return report;
    }

    std::vector<std::string> cleanup_targets = {
        scenario->reachable_content_id,
        scenario->reachable_commit_id,
        scenario->reachable_marker_id,
        scenario->expected_quarantine_id,
        scenario->expected_quarantine_meta_id,
    };
    report.cleanup = preflight::cleanup_owned_child(child_storage, owner_token, cleanup_targets, options.local_scratch);
    if (report.cleanup.result == "removed") {
        report.stage_reached = LiveGcStage::CleanupCompleted;
        report.status = "PASS";
    } else {
        report.status = "FAILED";
        report.error_message = "cleanup failed: " + report.cleanup.detail;
    }

    if (!options.output_path.empty()) {
        auto json_report = to_json(report);
        std::ofstream stream(options.output_path, std::ios::binary | std::ios::trunc);
        if (stream) {
            stream << json_report.dump(2) << '\n';
        }
    }

    return report;
}

nlohmann::json to_json(const RunnerReport& report) {
    nlohmann::json root{
        {"schema_version", report.schema_version},
        {"phase", report.phase},
        {"status", report.status},
        {"stage_reached", std::string{stage_name(report.stage_reached)}},
        {"error_message", report.error_message.empty() ? nlohmann::json(nullptr) : nlohmann::json(report.error_message)},
        {"remote_parent", report.remote_parent},
        {"effective_namespace", report.effective_namespace},
        {"pre_initialize", report.pre_initialize},
        {"post_initialize", report.post_initialize},
        {"ownership", {
            {"result", report.ownership.result},
            {"marker_written", report.ownership.marker_written},
            {"marker_readback_verified", report.ownership.marker_readback_verified},
        }},
        {"scenario", {
            {"reachable_identifier", report.scenario.reachable_identifier},
            {"candidate_identifier", report.scenario.candidate_identifier},
            {"candidate_sha256", report.scenario.candidate_sha256},
            {"quarantine_identifier", report.scenario.quarantine_identifier},
        }},
        {"gc", {
            {"called", report.gc.called},
            {"call_count", report.gc.call_count},
            {"result", report.gc.result},
            {"candidate_objects", report.gc.candidate_objects},
            {"quarantined_objects", report.gc.quarantined_objects},
            {"restored_objects", report.gc.restored_objects},
            {"purged_objects", report.gc.purged_objects},
            {"error_category", report.gc.error_category ? nlohmann::json(std::string{transport::error_code_name(*report.gc.error_category)}) : nlohmann::json(nullptr)},
            {"error_detail_sanitized", report.gc.error_detail_sanitized.empty() ? nlohmann::json(nullptr) : nlohmann::json(report.gc.error_detail_sanitized)},
        }},
        {"metrics", {
            {"verified_copy_source_physical_hash", report.metrics.verified_copy_source_physical_hash},
            {"verified_copy_native_copy", report.metrics.verified_copy_native_copy},
            {"verified_copy_native_copy_successes", report.metrics.verified_copy_native_copy_successes},
            {"verified_copy_destination_physical_hash", report.metrics.verified_copy_destination_physical_hash},
            {"verified_copy_native_copy_verifications", report.metrics.verified_copy_native_copy_verifications},
            {"gc_candidate_verified_copy", report.metrics.gc_candidate_verified_copy},
            {"gc_candidate_metadata_publish", report.metrics.gc_candidate_metadata_publish},
            {"gc_candidate_pre_remove_barrier_verification", report.metrics.gc_candidate_pre_remove_barrier_verification},
            {"gc_candidate_remove", report.metrics.gc_candidate_remove},
        }},
        {"validation", {
            {"reachable_preserved", report.validation.reachable_preserved},
            {"quarantine_present", report.validation.quarantine_present},
            {"quarantine_verified", report.validation.quarantine_verified},
            {"metadata_authenticated", report.validation.metadata_authenticated},
            {"source_removed", report.validation.source_removed},
            {"unexpected_removed", report.validation.unexpected_removed},
            {"unexpected_created", report.validation.unexpected_created},
        }},
        {"cleanup", {
            {"result", report.cleanup.result},
            {"detail", report.cleanup.detail},
            {"removed_objects", report.cleanup.removed_objects},
            {"error_category", report.cleanup.error_category ? nlohmann::json(std::string{transport::error_code_name(*report.cleanup.error_category)}) : nlohmann::json(nullptr)},
        }},
        {"not_measured", {
            {"client_payload_network_bytes", "NOT_MEASURED"},
            {"operations_copyfile_client_payload_bytes", "NOT_MEASURED"},
            {"rclone_internal_http_request_count", "NOT_MEASURED"},
            {"provider_internal_transfer_bytes", "NOT_MEASURED"},
            {"provider_side_copy", "NOT_MEASURED"},
        }},
    };

    auto inv_to_json = [](const StorageInventory& inv) {
        nlohmann::json arr = nlohmann::json::array();
        if (inv.owner_marker) {
            arr.push_back({{"identifier", *inv.owner_marker}, {"type", "operational_marker"}});
        }
        for (const auto& obj : inv.vault_objects) {
            arr.push_back({
                {"identifier", obj.identifier},
                {"size", obj.size},
                {"physical_sha256", obj.physical_sha256 ? nlohmann::json(*obj.physical_sha256) : nlohmann::json(nullptr)},
            });
        }
        return arr;
    };
    root["inventory_before"] = inv_to_json(report.inventory_before);
    root["inventory_after"] = inv_to_json(report.inventory_after);

    return root;
}

} // namespace kasumi::operational::gc_live_runner
