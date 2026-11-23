#include "application/use_cases/context.hpp"

#include "application/detail.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/history.hpp"
#include "application/profile.hpp"
#include "application/sync/journal.hpp"
#include "core/history.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/machine.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace kasumi::application::detail {

std::expected<void, Error> prepare_operation(const ExecutionInput& input,
                                             OperationContext& output) {
    wipe_operation(output);
    const auto operation = input.request.operation;
    output.operation = operation;
    output.app_data_dir = input.environment.app_data_dir;
    output.initial_sync = input.request.initial;
    output.audit_inventory = input.request.audit_inventory;
    output.repair = input.request.repair;
    output.dry_run = input.request.dry_run;
    output.reclaim_dirty = input.request.reclaim_dirty;
    output.gc_min_age_hours = input.request.gc_min_age_hours;
    output.writer_identifier = input.request.writer_identifier;
    output.barrier_identifier = input.request.barrier_identifier;
    output.on_progress = input.on_progress;
    const auto invalid_request = [&](std::string_view detail) {
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = std::string{detail},
        });
    };
    if (input.request.initial && operation != Operation::Sync) {
        return invalid_request("--initial is only valid for sync");
    }
    if (input.request.audit_inventory && operation != Operation::Sync) {
        return invalid_request("--audit-inventory is only valid for sync");
    }
    if (input.request.repair && operation != Operation::Sync) {
        return invalid_request("--repair is only valid for sync");
    }
    if (input.request.audit_inventory && input.request.initial) {
        return invalid_request(
            "--audit-inventory cannot be combined with --initial");
    }
    if (input.request.repair && input.request.initial) {
        return invalid_request("--repair cannot be combined with --initial");
    }
    if (input.request.dry_run && operation != Operation::Repack &&
        operation != Operation::GarbageCollect &&
        operation != Operation::ResolveMissing) {
        return invalid_request(
            "--dry-run is only valid for repack, gc, and resolve-missing");
    }
    if (input.request.confirm && operation != Operation::ResolveMissing) {
        return invalid_request("--confirm is only valid for resolve-missing");
    }
    if (input.request.confirm && input.request.dry_run) {
        return invalid_request("--confirm cannot be combined with --dry-run");
    }
    if (input.request.reclaim_dirty && operation != Operation::Repack) {
        return invalid_request("--reclaim-dirty is only valid for repack");
    }
    if (input.request.gc_min_age_hours.has_value()) {
        if (operation != Operation::GarbageCollect) {
            return invalid_request("--min-age is only valid for gc");
        }
        if (*input.request.gc_min_age_hours > 8760U) {
            return invalid_request(
                "--min-age must be between 0 and 8760 hours");
        }
    }
    if (operation == Operation::RemoveBarrier &&
        !input.request.confirm_abandoned) {
        return invalid_request(
            "--confirm-abandoned is required to remove a maintenance barrier");
    }
    const auto access_mode =
        (operation == Operation::Sync ||
         (operation == Operation::ResolveMissing && !input.request.dry_run))
            ? runtime::AccessMode::ReadWrite
            : runtime::AccessMode::ReadOnly;
    const auto fail = [&](std::string detail,
                          ErrorCode code = ErrorCode::RuntimeFailure,
                          bool with_summary =
                              true) -> std::expected<void, Error> {
        wipe_operation(output);
        return std::unexpected(Error{
            .operation = operation,
            .code = code,
            .detail = std::move(detail),
            .runtime =
                with_summary ? std::optional{output.summary} : std::nullopt,
        });
    };

    auto runtime_data = runtime::resolve(input.environment.app_data_dir,
                                         input.request.profile_name,
                                         access_mode);
    if (!runtime_data) {
        return fail(runtime_data.error().detail,
                    map_runtime_error_code(runtime_data.error().code,
                                           ErrorCode::InvalidProfile,
                                           ErrorCode::ProfileNotFound,
                                           ErrorCode::CredentialFailure,
                                           ErrorCode::RuntimeFailure,
                                           ErrorCode::RuntimeFailure),
                    false);
    }

    output.runtime = *runtime_data;
    output.summary =
        RuntimeSummary{.local_dir = runtime_data->local_dir,
                       .remote_dir = runtime_data->storage_location};
    if (runtime_data->min_history_depth == 0 ||
        runtime_data->min_history_depth > history::maximum_graph_depth ||
        runtime_data->min_history_age_hours == 0) {
        return fail("invalid retention policy");
    }
    const bool needs_machine_identity =
        !(operation == Operation::Status || operation == Operation::Preview ||
          ((operation == Operation::Repack ||
            operation == Operation::GarbageCollect ||
            operation == Operation::ResolveMissing) &&
           input.request.dry_run));
    if (needs_machine_identity) {
        auto identity = runtime::resolve_machine_identity(
            input.environment.app_data_dir, true);
        if (!identity) {
            return fail(identity.error().detail);
        }
        output.machine_identity = std::move(*identity);
    }
    auto profile_lock = platform::acquire_profile_lock(
        input.environment.app_data_dir /
        ("profile-" + input.request.profile_name + ".lock"));
    if (!profile_lock) {
        auto lock_detail = profile_lock.error();
        const bool is_lock_busy =
            lock_detail == "profile is already in use by another execution";
        if (is_lock_busy) {
            if (const auto active_op =
                    active_profile_operation(inspect_profile_activity(
                        input.environment, input.request.profile_name))) {
                lock_detail =
                    std::format("{} (running {})", lock_detail, *active_op);
            }
        }
        const auto summary = output.summary;
        wipe_operation(output);
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = std::move(lock_detail),
            .runtime = summary,
            .lock_busy = is_lock_busy,
        });
    }
    output.profile_lock = *profile_lock;

    if (input.request.initial) {
        const auto inspect_status = [](const std::filesystem::path& path,
                                       const char* context_label)
            -> std::expected<std::filesystem::file_status, std::string> {
            std::error_code error;
            const auto status = std::filesystem::symlink_status(path, error);
            if (error && error != std::errc::no_such_file_or_directory &&
                error != std::errc::not_a_directory) {
                return std::unexpected(std::string(context_label) + ": " +
                                       error.message());
            }
            return status;
        };
        const auto check_absent = [&](const std::filesystem::path& path)
            -> std::optional<std::string> {
            const auto status = inspect_status(
                path, "cannot inspect local initialization state");
            if (!status) {
                return status.error();
            }
            if (status->type() != std::filesystem::file_type::not_found) {
                return "initial sync requires absent local state; existing "
                       "database or transaction evidence was left untouched";
            }
            return std::nullopt;
        };
        const auto check_empty_directory =
            [&](const std::filesystem::path& path)
            -> std::optional<std::string> {
            const auto status = inspect_status(
                path, "cannot inspect local transaction workspaces");
            if (!status) {
                return status.error();
            }
            if (status->type() == std::filesystem::file_type::not_found) {
                return std::nullopt;
            }
            if (std::filesystem::is_symlink(*status) ||
                !std::filesystem::is_directory(*status)) {
                return "initial sync requires a physical transaction "
                       "workspace directory";
            }
            std::error_code error;
            std::filesystem::directory_iterator entry(path, error);
            if (error) {
                return "cannot list local transaction workspaces: " +
                       error.message();
            }
            if (entry != std::filesystem::directory_iterator{}) {
                return "initial sync found existing transaction workspace "
                       "evidence; local state was left untouched";
            }
            return std::nullopt;
        };

        const auto db_status =
            inspect_status(runtime_data->database_path,
                           "cannot inspect local initialization state");
        if (!db_status) {
            return fail(db_status.error());
        }
        if (db_status->type() != std::filesystem::file_type::not_found) {
            if (std::filesystem::is_symlink(*db_status) ||
                !std::filesystem::is_regular_file(*db_status) ||
                !state_storage::validate(runtime_data->database_path)) {
                return fail(
                    "initial sync requires absent local state; existing "
                    "database or transaction evidence was left untouched");
            }
            const auto loaded =
                state_storage::load_state(runtime_data->database_path);
            if (!loaded || loaded->has_value()) {
                return fail(
                    "initial sync requires absent local state; existing "
                    "database or transaction evidence was left untouched");
            }
        }

        const auto profile_directory =
            runtime_data->database_path.parent_path();
        const auto journal_paths = sync::journal::make_paths(profile_directory);
        if (!journal_paths) {
            return fail("cannot inspect local transaction state: " +
                        journal_paths.error());
        }
        const auto sidecars = sqlite_sidecar_paths(runtime_data->database_path);
        for (const auto& path : {
                 sidecars[0],
                 sidecars[1],
                 sidecars[2],
                 journal_paths->final_path.parent_path(),
                 profile_directory / "transaction.bin.enc.cleared",
             }) {
            if (auto error = check_absent(path)) {
                return fail(*error);
            }
        }
        if (auto error =
                check_empty_directory(profile_directory / ".transactions")) {
            return fail(*error);
        }
    } else if (operation != Operation::RemoveBarrier &&
               !state_storage::validate(runtime_data->database_path)) {
        return fail("profile state database is missing, corrupt, or "
                    "uses an unsupported schema; existing data was "
                    "left untouched");
    }
    // Resolves and validates the key from the provided credentials.
    auto key = resolve_vault_key<Error>(
        input.credentials,
        *runtime_data,
        output.key,
        VaultKeyPolicy<Error>{
            .read_only = false,
            .missing_code = ErrorCode::CredentialFailure,
            .mismatch_code = ErrorCode::RuntimeFailure,
            .io_code = ErrorCode::CredentialFailure,
            .credential_code = ErrorCode::CredentialFailure,
            .missing_detail = "key not found and credentials not provided",
        },
        [&](ErrorCode code, std::string detail) {
            return make_error(output, code, std::move(detail));
        });
    if (!key) {
        wipe_operation(output);
        return std::unexpected(key.error());
    }

    auto opened_storage = transport::open_transport(
        runtime_data->storage_location, runtime_data->local_dir);
    if (!opened_storage) {
        return fail(transport::describe(opened_storage.error()));
    }

    if (input.request.initial) {
        auto initialized = transport::initialize(*opened_storage);
        if (!initialized) {
            return fail("cannot initialize remote storage: " +
                        transport::describe(initialized.error()));
        }
        auto identifiers = transport::list(*opened_storage);
        if (!identifiers) {
            return fail("cannot verify remote protocol state: " +
                        transport::describe(identifiers.error()));
        }
        const auto layout = history_storage::derive_remote_layout(output.key);
        const bool has_remote_history =
            std::ranges::any_of(*identifiers, [&](const std::string& id) {
                return id.starts_with(layout.history_prefix);
            });
        if (has_remote_history) {
            const auto profile_dir = runtime_data->database_path.parent_path();
            auto observed = observation::history::observe(
                *opened_storage, output.key, profile_dir, false);
            if (!observed) {
                return fail("remote history is invalid, corrupt, or "
                            "unauthenticated: " +
                            observed.error().detail);
            }
            if (!observed->history_present) {
                return fail("remote history namespace contains partial or "
                            "unrecognized objects without valid head markers; "
                            "remote objects were left untouched");
            }
            output.has_remote_history_objects = true;
        }
        if (!state_storage::initialize(runtime_data->database_path) ||
            !state_storage::validate(runtime_data->database_path)) {
            return fail("failed to initialize the missing profile state "
                        "database; inspect local state before retrying");
        }
    }

    output.storage = std::move(*opened_storage);
    return {};
}

void wipe_operation(OperationContext& context) noexcept {
    crypto::secure_memory::wipe(context.key.data(), context.key.size());
    context.app_data_dir.clear();
    context.machine_identity.reset();
    context.accepted_commit_id.clear();
    context.recovered_transaction = false;
    context.sync_mutated = false;
    context.remote_observed = false;
    context.on_sync_mutation_start = {};
    context.maintenance_failure_outcome.reset();
    context.maintenance_failure_stage.clear();
    context.maintenance_failure_detail.clear();
    context.maintenance_metric_primary = 0;
    context.maintenance_metric_secondary = 0;
    context.maintenance_flags = 0;
    context.gc_kept_activities.clear();
    platform::release_profile_lock(context.profile_lock);
}

} // namespace kasumi::application::detail
