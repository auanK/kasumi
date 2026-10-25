#include "application/use_cases/context.hpp"

#include "application/history_storage/remote_layout.hpp"
#include "application/observation/history.hpp"
#include "application/sync/journal.hpp"
#include "application/use_cases/error_mapping.hpp"
#include "core/history.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/perf_trace.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <filesystem>
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
    output.initial_sync = input.request.initial;
    output.audit_inventory = input.request.audit_inventory;
    output.trust_existing_content = input.request.trust_existing_content;
    output.writer_identifier = input.request.writer_identifier;
    output.on_progress = input.on_progress;
    if (input.request.initial && operation != Operation::Sync) {
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = "--initial is only valid for sync",
        });
    }
    if (input.request.trust_existing_content && !input.request.initial) {
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = "--trust-existing-content requires --initial",
        });
    }
    if (input.request.trust_existing_content && operation != Operation::Sync) {
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = "--trust-existing-content is only valid for sync",
        });
    }
    if (input.request.audit_inventory && operation != Operation::Sync) {
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = "--audit-inventory is only valid for sync",
        });
    }
    if (input.request.audit_inventory && input.request.initial) {
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = "--audit-inventory cannot be combined with --initial",
        });
    }
    const auto access_mode =
        (operation == Operation::Sync || operation == Operation::ResolveMissing)
            ? runtime::AccessMode::ReadWrite
            : runtime::AccessMode::ReadOnly;
    const auto resolve_trace = platform::perf_trace::begin();
    auto runtime_data = runtime::resolve(input.environment.app_data_dir,
                                         input.request.profile_name,
                                         access_mode);
    platform::perf_trace::finish("runtime/profile resolve", resolve_trace);
    if (!runtime_data) {
        return std::unexpected(Error{
            .operation = operation,
            .code =
                runtime_error_to_application_error(runtime_data.error().code),
            .detail = runtime_data.error().detail,
            .runtime = std::nullopt,
        });
    }

    output.runtime = *runtime_data;
    output.summary =
        RuntimeSummary{.local_dir = runtime_data->local_dir,
                       .remote_dir = runtime_data->storage_location};
    if (runtime_data->min_history_depth == 0 ||
        runtime_data->min_history_depth > history::maximum_graph_depth ||
        runtime_data->min_history_age_hours == 0) {
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = "invalid retention policy",
            .runtime = output.summary,
        });
    }
    const auto preparation_trace = platform::perf_trace::begin();
    auto profile_lock = platform::acquire_profile_lock(
        input.environment.app_data_dir /
        ("profile-" + input.request.profile_name + ".lock"));
    if (!profile_lock) {
        platform::perf_trace::finish("operation preparation",
                                     preparation_trace);
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = profile_lock.error(),
            .runtime = output.summary,
        });
    }
    output.profile_lock = *profile_lock;

    if (input.request.initial) {
        const auto reject_initial = [&](std::string detail)
            -> std::expected<void, Error> {
            platform::perf_trace::finish("operation preparation",
                                         preparation_trace);
            wipe_operation(output);
            return std::unexpected(Error{
                .operation = operation,
                .code = ErrorCode::RuntimeFailure,
                .detail = std::move(detail),
                .runtime = output.summary,
            });
        };
        const auto check_absent = [](const std::filesystem::path& path)
            -> std::optional<std::string> {
            std::error_code error;
            const auto status = std::filesystem::symlink_status(path, error);
            if (error == std::errc::no_such_file_or_directory ||
                error == std::errc::not_a_directory) {
                return std::nullopt;
            }
            if (error) {
                return "cannot inspect local initialization state: " +
                       error.message();
            }
            if (status.type() != std::filesystem::file_type::not_found) {
                return "initial sync requires absent local state; existing "
                       "database or transaction evidence was left untouched";
            }
            return std::nullopt;
        };
        const auto check_empty_directory = [](const std::filesystem::path& path)
            -> std::optional<std::string> {
            std::error_code error;
            const auto status = std::filesystem::symlink_status(path, error);
            if (error == std::errc::no_such_file_or_directory ||
                error == std::errc::not_a_directory) {
                return std::nullopt;
            }
            if (error) {
                return "cannot inspect local transaction workspaces: " +
                       error.message();
            }
            if (status.type() == std::filesystem::file_type::not_found) {
                return std::nullopt;
            }
            if (std::filesystem::is_symlink(status) ||
                !std::filesystem::is_directory(status)) {
                return "initial sync requires a physical transaction "
                       "workspace directory";
            }
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

        std::error_code db_err;
        const auto db_status =
            std::filesystem::symlink_status(runtime_data->database_path, db_err);
        if (db_err && db_err != std::errc::no_such_file_or_directory) {
            return reject_initial("cannot inspect local initialization state: " +
                                  db_err.message());
        }
        if (db_status.type() != std::filesystem::file_type::not_found) {
            if (std::filesystem::is_symlink(db_status) ||
                !std::filesystem::is_regular_file(db_status)) {
                return reject_initial(
                    "initial sync requires absent local state; existing "
                    "database or transaction evidence was left untouched");
            }
            if (!state_storage::validate(runtime_data->database_path)) {
                return reject_initial(
                    "initial sync requires absent local state; existing "
                    "database or transaction evidence was left untouched");
            }
            auto loaded =
                state_storage::load_state(runtime_data->database_path);
            if (!loaded || loaded->has_value()) {
                return reject_initial(
                    "initial sync requires absent local state; existing "
                    "database or transaction evidence was left untouched");
            }
        }

        auto wal_path = runtime_data->database_path;
        wal_path += "-wal";
        auto shm_path = runtime_data->database_path;
        shm_path += "-shm";
        auto journal_path = runtime_data->database_path;
        journal_path += "-journal";
        const auto profile_directory =
            runtime_data->database_path.parent_path();
        const auto journal_paths = sync::journal::make_paths(profile_directory);
        if (!journal_paths) {
            return reject_initial("cannot inspect local transaction state: " +
                                  journal_paths.error());
        }
        const std::vector<std::filesystem::path> evidence{
            wal_path,
            shm_path,
            journal_path,
            journal_paths->final_path.parent_path(),
            profile_directory / "transaction.bin.enc.cleared",
        };
        for (const auto& path : evidence) {
            if (auto error = check_absent(path)) {
                return reject_initial(*error);
            }
        }
        if (auto error =
                check_empty_directory(profile_directory / ".transactions")) {
            return reject_initial(*error);
        }
    } else if (!state_storage::validate(runtime_data->database_path)) {
        platform::perf_trace::finish("operation preparation",
                                     preparation_trace);
        wipe_operation(output);
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = "profile state database is missing, corrupt, or "
                      "uses an unsupported schema; existing data was "
                      "left untouched",
            .runtime = output.summary,
        });
    }
    auto key = resolve_key_into(operation,
                                input.credentials,
                                *runtime_data,
                                output.summary,
                                output.key);
    if (!key) {
        platform::perf_trace::finish("operation preparation",
                                     preparation_trace);
        wipe_operation(output);
        return std::unexpected(key.error());
    }
    platform::perf_trace::finish("operation preparation", preparation_trace);

    const auto transport_trace = platform::perf_trace::begin();
    auto opened_storage = transport::open_transport(
        runtime_data->storage_location, runtime_data->local_dir);
    platform::perf_trace::finish("transport open", transport_trace);
    if (!opened_storage) {
        wipe_operation(output);
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = transport::describe(opened_storage.error()),
            .runtime = output.summary,
        });
    }

    if (input.request.initial) {
        auto initialized = transport::initialize(*opened_storage);
        if (!initialized) {
            wipe_operation(output);
            return std::unexpected(Error{
                .operation = operation,
                .code = ErrorCode::RuntimeFailure,
                .detail = "cannot initialize remote storage: " +
                          transport::describe(initialized.error()),
                .runtime = output.summary,
            });
        }
        auto identifiers = transport::list(*opened_storage);
        if (!identifiers) {
            wipe_operation(output);
            return std::unexpected(Error{
                .operation = operation,
                .code = ErrorCode::RuntimeFailure,
                .detail = "cannot verify remote protocol state: " +
                          transport::describe(identifiers.error()),
                .runtime = output.summary,
            });
        }
        const auto layout = history_storage::derive_remote_layout(output.key);
        const bool has_remote_history =
            std::ranges::any_of(*identifiers, [&](const std::string& id) {
                return id.starts_with(layout.history_prefix);
            });
        if (has_remote_history && input.request.trust_existing_content) {
            wipe_operation(output);
            return std::unexpected(Error{
                .operation = operation,
                .code = ErrorCode::RuntimeFailure,
                .detail = "--trust-existing-content is only valid when "
                          "bootstrapping an empty remote history",
                .runtime = output.summary,
            });
        }
        if (has_remote_history) {
            const auto profile_dir = runtime_data->database_path.parent_path();
            auto observed = observation::history::observe(
                *opened_storage,
                output.key,
                profile_dir,
                false);
            if (!observed) {
                wipe_operation(output);
                return std::unexpected(Error{
                    .operation = operation,
                    .code = ErrorCode::RuntimeFailure,
                    .detail = "remote history is invalid, corrupt, or unauthenticated: " +
                              observed.error().detail,
                    .runtime = output.summary,
                });
            }
            if (!observed->history_present) {
                wipe_operation(output);
                return std::unexpected(Error{
                    .operation = operation,
                    .code = ErrorCode::RuntimeFailure,
                    .detail = "remote history namespace contains partial or "
                              "unrecognized objects without valid head markers; "
                              "remote objects were left untouched",
                    .runtime = output.summary,
                });
            }
            output.has_remote_history_objects = true;
        }
        if (!state_storage::initialize(runtime_data->database_path) ||
            !state_storage::validate(runtime_data->database_path)) {
            wipe_operation(output);
            return std::unexpected(Error{
                .operation = operation,
                .code = ErrorCode::RuntimeFailure,
                .detail = "failed to initialize the missing profile state "
                          "database; inspect local state before retrying",
                .runtime = output.summary,
            });
        }
    }

    output.storage = std::move(*opened_storage);
    return {};
}

void wipe_operation(OperationContext& context) noexcept {
    crypto::secure_memory::wipe(context.key.data(), context.key.size());
    platform::release_profile_lock(context.profile_lock);
}

} // namespace kasumi::application::detail
