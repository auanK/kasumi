#include "application/integrity/maintenance.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/quarantine_variant.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/cancellation.hpp"

#include <algorithm>
#include <chrono>
#include <utility>

namespace kasumi::application::integrity {
namespace {

namespace protocol = history_storage::maintenance_protocol;
using Failure = GcAnalysisErrorCode;
using Analysis = std::expected<GcSnapshot, GcAnalysisError>;

GcAnalysisError failure(Failure code, Error cause) {
    return {.code = code, .cause = std::move(cause), .cleanup_error = std::nullopt};
}

Error protocol_error(const protocol::Error& source) {
    ErrorCode code = ErrorCode::IntegrityFailure;
    switch (source.code) {
    case protocol::ErrorCode::InvalidInput: code = ErrorCode::InvalidInput; break;
    case protocol::ErrorCode::WorkspaceFailure: code = ErrorCode::WorkspaceFailure; break;
    case protocol::ErrorCode::TransportFailure: code = ErrorCode::TransportFailure; break;
    case protocol::ErrorCode::Blocked: code = ErrorCode::ConcurrentChange; break;
    default: break;
    }
    return {.code = code, .detail = source.detail, .object_identifier = std::nullopt};
}

Error transport_error(const transport::Error& source, std::string identifier = {}) {
    return {.code = ErrorCode::TransportFailure,
            .detail = transport::describe(source),
            .object_identifier = identifier.empty() ? std::nullopt
                : std::optional<std::string>{std::move(identifier)}};
}

GcAnalysisError cancelled() {
    return failure(Failure::Cancelled,
                   {.code = ErrorCode::ConcurrentChange,
                    .detail = "GC analysis cancelled", .object_identifier = std::nullopt});
}

std::expected<void, GcAnalysisError>
check_writers(transport::Transport& storage, const history_storage::RemoteLayout& layout,
              Failure on_error) {
    auto writers = protocol::active_writers(storage, layout);
    if (!writers) return std::unexpected(failure(on_error, protocol_error(writers.error())));
    if (!writers->empty()) {
        return std::unexpected(failure(Failure::WriterPresent,
            {.code = ErrorCode::ConcurrentChange,
             .detail = "registered writers block exclusive GC analysis",
             .object_identifier = writers->front()}));
    }
    return {};
}

std::expected<void, GcAnalysisError>
check_owner(const protocol::RegistrationState& barrier) {
    if (auto verified = protocol::verify_registration(barrier); !verified) {
        return std::unexpected(failure(Failure::OwnershipLost, protocol_error(verified.error())));
    }
    return {};
}

std::expected<void, GcAnalysisError>
check_observed_writers(const GcSnapshot& snapshot, const history_storage::RemoteLayout& layout) {
    const auto writer = std::ranges::find_if(snapshot.physical_namespace,
        [&](const auto& id) { return id.starts_with(layout.writers_prefix); });
    if (writer != snapshot.physical_namespace.end()) {
        return std::unexpected(failure(Failure::WriterPresent,
            {.code = ErrorCode::ConcurrentChange, .detail = "writer observed in GC snapshot",
             .object_identifier = *writer}));
    }
    return {};
}

std::expected<void, Error> release_barrier(protocol::RegistrationState& barrier) {
    // Check explicitly: release_registration alone silently preserves a foreign owner.
    if (auto verified = protocol::verify_registration(barrier); !verified)
        return std::unexpected(protocol_error(verified.error()));
    auto& storage = *barrier.storage;
    if (auto released = protocol::release_registration(barrier); !released)
        return std::unexpected(protocol_error(released.error()));
    auto present = transport::presence(storage, barrier.identifier);
    if (!present) return std::unexpected(transport_error(present.error(), barrier.identifier));
    if (*present != transport::Presence::Absent) {
        return std::unexpected(Error{.code = ErrorCode::ConcurrentChange,
            .detail = "barrier release could not be confirmed",
            .object_identifier = barrier.identifier});
    }
    return {};
}

constexpr GcContentRemovalErrorCode to_removal_code(GcAnalysisErrorCode code) noexcept {
    switch (code) {
    case GcAnalysisErrorCode::Preconditions: return GcContentRemovalErrorCode::Preconditions;
    case GcAnalysisErrorCode::BarrierAcquisition: return GcContentRemovalErrorCode::BarrierAcquisition;
    case GcAnalysisErrorCode::WriterPresent: return GcContentRemovalErrorCode::WriterPresent;
    case GcAnalysisErrorCode::OwnershipLost: return GcContentRemovalErrorCode::OwnershipLost;
    case GcAnalysisErrorCode::Observation: return GcContentRemovalErrorCode::Observation;
    case GcAnalysisErrorCode::SnapshotChanged: return GcContentRemovalErrorCode::SnapshotChanged;
    case GcAnalysisErrorCode::BarrierRelease: return GcContentRemovalErrorCode::BarrierRelease;
    case GcAnalysisErrorCode::Cancelled: return GcContentRemovalErrorCode::Cancelled;
    }
    return GcContentRemovalErrorCode::Preconditions;
}

using RemovalFailure = GcContentRemovalErrorCode;

GcContentRemovalError content_removal_failure(
    RemovalFailure code,
    Error cause,
    std::size_t removed = 0,
    std::size_t absent = 0,
    bool uncertain = false) {
    return {
        .code = code,
        .cause = std::move(cause),
        .cleanup_error = std::nullopt,
        .removed_content = removed,
        .already_absent = absent,
        .uncertain_mutation = uncertain,
    };
}

GcContentRemovalError content_removal_cancelled(
    std::size_t removed = 0,
    std::size_t absent = 0) {
    return content_removal_failure(
        RemovalFailure::Cancelled,
        {.code = ErrorCode::ConcurrentChange,
         .detail = "GC content removal cancelled",
         .object_identifier = std::nullopt},
        removed,
        absent);
}

constexpr GcCommitQuarantineErrorCode to_quarantine_code(GcAnalysisErrorCode code) noexcept {
    switch (code) {
    case GcAnalysisErrorCode::Preconditions: return GcCommitQuarantineErrorCode::Preconditions;
    case GcAnalysisErrorCode::BarrierAcquisition: return GcCommitQuarantineErrorCode::BarrierAcquisition;
    case GcAnalysisErrorCode::WriterPresent: return GcCommitQuarantineErrorCode::WriterPresent;
    case GcAnalysisErrorCode::OwnershipLost: return GcCommitQuarantineErrorCode::OwnershipLost;
    case GcAnalysisErrorCode::Observation: return GcCommitQuarantineErrorCode::Observation;
    case GcAnalysisErrorCode::SnapshotChanged: return GcCommitQuarantineErrorCode::SnapshotChanged;
    case GcAnalysisErrorCode::BarrierRelease: return GcCommitQuarantineErrorCode::BarrierRelease;
    case GcAnalysisErrorCode::Cancelled: return GcCommitQuarantineErrorCode::Cancelled;
    }
    return GcCommitQuarantineErrorCode::Preconditions;
}

using QuarantineFailure = GcCommitQuarantineErrorCode;

Error history_storage_error(const history_storage::Error& source) {
    ErrorCode code = ErrorCode::IntegrityFailure;
    switch (source.code) {
    case history_storage::ErrorCode::InvalidInput:
    case history_storage::ErrorCode::InvalidIdentifier:
        code = ErrorCode::InvalidInput;
        break;
    case history_storage::ErrorCode::WorkspaceFailure:
        code = ErrorCode::WorkspaceFailure;
        break;
    case history_storage::ErrorCode::TransportFailure:
        code = ErrorCode::TransportFailure;
        break;
    default:
        break;
    }
    return {.code = code, .detail = source.detail, .object_identifier = std::nullopt};
}

GcCommitQuarantineError commit_quarantine_failure(
    QuarantineFailure code,
    Error cause,
    const GcCommitQuarantineResult& current_result,
    bool uncertain = false) {
    return {
        .code = code,
        .cause = std::move(cause),
        .cleanup_error = std::nullopt,
        .commit_candidates = current_result.commit_candidates,
        .payloads_verified = current_result.payloads_verified,
        .records_confirmed = current_result.records_confirmed,
        .quarantined = current_result.quarantined,
        .originals_removed = current_result.originals_removed,
        .already_absent = current_result.already_absent,
        .uncertain_mutation = uncertain,
    };
}

GcCommitQuarantineError commit_quarantine_cancelled(
    const GcCommitQuarantineResult& current_result) {
    return commit_quarantine_failure(
        QuarantineFailure::Cancelled,
        {.code = ErrorCode::ConcurrentChange,
         .detail = "GC commit quarantine cancelled",
         .object_identifier = std::nullopt},
        current_result);
}

struct StableGcObservation {
    protocol::RegistrationState barrier;
    history_storage::RemoteLayout layout;
    GcSnapshot snapshot;
};

std::expected<StableGcObservation, GcAnalysisError>
acquire_and_observe_gc(transport::Transport& storage,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                       const std::filesystem::path& workspace_root) {
    std::error_code error;
    if (!transport::valid(storage) || workspace_root.empty() ||
        !std::filesystem::is_directory(workspace_root, error)) {
        return std::unexpected(failure(Failure::Preconditions,
            {.code = ErrorCode::InvalidInput, .detail = "invalid GC analysis context",
             .object_identifier = std::nullopt}));
    }
    if (platform::cancellation::requested()) return std::unexpected(cancelled());
    if (auto initialized = transport::initialize(storage); !initialized)
        return std::unexpected(failure(Failure::Preconditions, transport_error(initialized.error())));
    const auto layout = history_storage::derive_remote_layout(key);
    if (auto writers = check_writers(storage, layout, Failure::Preconditions); !writers)
        return std::unexpected(std::move(writers.error()));
    if (platform::cancellation::requested()) return std::unexpected(cancelled());

    auto barrier = protocol::establish_barrier(storage, layout, workspace_root);
    if (!barrier) {
        auto cause = protocol_error(barrier.error());
        cause.object_identifier = layout.barrier_identifier;
        cause.detail += "; no confirmed registration available for cleanup";
        return std::unexpected(failure(platform::cancellation::requested()
            ? Failure::Cancelled : Failure::BarrierAcquisition, std::move(cause)));
    }

    auto observed = [&]() -> Analysis {
        if (platform::cancellation::requested()) return std::unexpected(cancelled());
        if (auto owner = check_owner(*barrier); !owner) return std::unexpected(std::move(owner.error()));
        if (auto writers = check_writers(storage, layout, Failure::OwnershipLost); !writers)
            return std::unexpected(std::move(writers.error()));
        if (platform::cancellation::requested()) return std::unexpected(cancelled());
        if (auto owner = check_owner(*barrier); !owner) return std::unexpected(std::move(owner.error()));

        auto first = collect_gc_snapshot(storage, key, workspace_root);
        if (!first) return std::unexpected(failure(platform::cancellation::requested()
            ? Failure::Cancelled : Failure::Observation, std::move(first.error())));
        if (platform::cancellation::requested()) return std::unexpected(cancelled());
        if (auto writers = check_observed_writers(*first, layout); !writers)
            return std::unexpected(std::move(writers.error()));
        auto second = collect_gc_snapshot(storage, key, workspace_root);
        if (!second) return std::unexpected(failure(platform::cancellation::requested()
            ? Failure::Cancelled : Failure::Observation, std::move(second.error())));
        if (platform::cancellation::requested()) return std::unexpected(cancelled());
        if (auto writers = check_observed_writers(*second, layout); !writers)
            return std::unexpected(std::move(writers.error()));
        if (!same_gc_snapshot(*first, *second)) {
            return std::unexpected(failure(Failure::SnapshotChanged,
                {.code = ErrorCode::ConcurrentChange, .detail = "GC observations differ",
                 .object_identifier = std::nullopt}));
        }
        if (auto writers = check_writers(storage, layout, Failure::OwnershipLost); !writers)
            return std::unexpected(std::move(writers.error()));
        if (auto owner = check_owner(*barrier); !owner) return std::unexpected(std::move(owner.error()));
        if (platform::cancellation::requested()) return std::unexpected(cancelled());
        return std::move(*second);
    }();

    if (!observed) {
        auto cleanup = release_barrier(*barrier);
        if (!cleanup) observed.error().cleanup_error = std::move(cleanup.error());
        return std::unexpected(std::move(observed.error()));
    }

    return StableGcObservation{
        .barrier = std::move(*barrier),
        .layout = layout,
        .snapshot = std::move(*observed),
    };
}

} // namespace

Analysis analyze_gc_under_barrier(transport::Transport& storage,
                                  std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                                  const std::filesystem::path& workspace_root) {
    auto session = acquire_and_observe_gc(storage, key, workspace_root);
    if (!session) {
        return std::unexpected(std::move(session.error()));
    }

    auto cleanup = release_barrier(session->barrier);
    if (!cleanup) {
        return std::unexpected(failure(Failure::BarrierRelease, std::move(cleanup.error())));
    }
    if (platform::cancellation::requested()) return std::unexpected(cancelled());
    return std::move(session->snapshot);
}

std::expected<GcContentRemovalResult, GcContentRemovalError>
remove_orphan_content_under_barrier(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_root) {
    auto session = acquire_and_observe_gc(storage, key, workspace_root);
    if (!session) {
        auto& err = session.error();
        return std::unexpected(GcContentRemovalError{
            .code = to_removal_code(err.code),
            .cause = std::move(err.cause),
            .cleanup_error = std::move(err.cleanup_error),
            .removed_content = 0,
            .already_absent = 0,
            .uncertain_mutation = false,
        });
    }

    GcContentRemovalResult result;
    for (const auto& candidate : session->snapshot.candidates) {
        if (candidate.kind == GcCandidateKind::Content) {
            ++result.content_candidates;
        } else if (candidate.kind == GcCandidateKind::CommitVariant) {
            ++result.pending_commit_variants;
        }
    }

    std::optional<GcContentRemovalError> removal_failure;

    for (const auto& candidate : session->snapshot.candidates) {
        if (candidate.kind != GcCandidateKind::Content) {
            continue;
        }

        if (platform::cancellation::requested()) {
            removal_failure = content_removal_cancelled(result.removed_content, result.already_absent);
            break;
        }

        if (auto owner = check_owner(session->barrier); !owner) {
            removal_failure = content_removal_failure(
                RemovalFailure::OwnershipLost,
                std::move(owner.error().cause),
                result.removed_content,
                result.already_absent);
            break;
        }

        if (auto writers = check_writers(storage, session->layout, Failure::OwnershipLost); !writers) {
            removal_failure = content_removal_failure(
                writers.error().code == Failure::WriterPresent
                    ? RemovalFailure::WriterPresent
                    : RemovalFailure::OwnershipLost,
                std::move(writers.error().cause),
                result.removed_content,
                result.already_absent);
            break;
        }

        auto pres = transport::presence(storage, candidate.identifier);
        if (!pres) {
            removal_failure = content_removal_failure(
                RemovalFailure::Observation,
                transport_error(pres.error(), candidate.identifier),
                result.removed_content,
                result.already_absent);
            break;
        }

        if (*pres == transport::Presence::Absent) {
            ++result.already_absent;
            continue;
        }

        auto rem = storage.storage.remove(storage.state.get(), candidate.identifier);
        if (rem.has_value()) {
            if (*rem == transport::Removal::Removed) {
                ++result.removed_content;
            } else if (*rem == transport::Removal::AlreadyAbsent) {
                ++result.already_absent;
            }
        } else {
            auto primary_cause = transport_error(rem.error(), candidate.identifier);
            if (platform::cancellation::requested()) {
                removal_failure = GcContentRemovalError{
                    .code = RemovalFailure::Cancelled,
                    .cause = std::move(primary_cause),
                    .cleanup_error = std::nullopt,
                    .removed_content = result.removed_content,
                    .already_absent = result.already_absent,
                    .uncertain_mutation = true,
                };
                break;
            }
            removal_failure = content_removal_failure(
                RemovalFailure::RemovalFailure,
                std::move(primary_cause),
                result.removed_content,
                result.already_absent,
                true);
            break;
        }
    }

    if (!removal_failure && platform::cancellation::requested()) {
        removal_failure = content_removal_cancelled(result.removed_content, result.already_absent);
    }

    auto cleanup = release_barrier(session->barrier);
    if (removal_failure) {
        if (!cleanup) {
            removal_failure->cleanup_error = std::move(cleanup.error());
        }
        return std::unexpected(std::move(*removal_failure));
    }

    if (!cleanup) {
        return std::unexpected(content_removal_failure(
            RemovalFailure::BarrierRelease,
            std::move(cleanup.error()),
            result.removed_content,
            result.already_absent));
    }

    if (platform::cancellation::requested()) {
        return std::unexpected(content_removal_cancelled(result.removed_content, result.already_absent));
    }

    return result;
}

std::expected<GcCommitQuarantineResult, GcCommitQuarantineError>
quarantine_commit_variants_under_barrier(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_root) {
    auto session = acquire_and_observe_gc(storage, key, workspace_root);
    if (!session) {
        auto& err = session.error();
        return std::unexpected(GcCommitQuarantineError{
            .code = to_quarantine_code(err.code),
            .cause = std::move(err.cause),
            .cleanup_error = std::move(err.cleanup_error),
            .commit_candidates = 0,
            .payloads_verified = 0,
            .records_confirmed = 0,
            .quarantined = 0,
            .originals_removed = 0,
            .already_absent = 0,
            .uncertain_mutation = false,
        });
    }

    GcCommitQuarantineResult result;
    for (const auto& candidate : session->snapshot.candidates) {
        if (candidate.kind == GcCandidateKind::CommitVariant) {
            ++result.commit_candidates;
        } else if (candidate.kind == GcCandidateKind::Content) {
            ++result.pending_content_candidates;
        }
    }

    auto temporary_ws = history_storage::detail::make_workspace(workspace_root);
    if (!temporary_ws) {
        auto cleanup = release_barrier(session->barrier);
        auto err = commit_quarantine_failure(
            QuarantineFailure::Preconditions,
            history_storage_error(temporary_ws.error()),
            result);
        if (!cleanup) {
            err.cleanup_error = std::move(cleanup.error());
        }
        return std::unexpected(std::move(err));
    }

    std::optional<GcCommitQuarantineError> quarantine_failure;
    std::size_t item_sequence = 0;

    for (const auto& candidate : session->snapshot.candidates) {
        if (candidate.kind != GcCandidateKind::CommitVariant) {
            continue;
        }

        ++item_sequence;
        const auto item_tag = std::to_string(item_sequence);
        const auto candidate_ciphertext_path = (*temporary_ws)->root / ("cand-cipher-" + item_tag);
        const auto candidate_plaintext_path = (*temporary_ws)->root / ("cand-plain-" + item_tag);
        const auto readback_payload_path = (*temporary_ws)->root / ("rb-payload-" + item_tag);
        const auto local_record_path = (*temporary_ws)->root / ("local-record-" + item_tag);
        const auto readback_record_path = (*temporary_ws)->root / ("rb-record-" + item_tag);

        auto cleanup_temp_files = [&]() noexcept {
            history_storage::detail::remove_file(candidate_ciphertext_path);
            history_storage::detail::remove_file(candidate_plaintext_path);
            history_storage::detail::remove_file(readback_payload_path);
            history_storage::detail::remove_file(local_record_path);
            history_storage::detail::remove_file(readback_record_path);
        };

        if (platform::cancellation::requested()) {
            quarantine_failure = commit_quarantine_cancelled(result);
            cleanup_temp_files();
            break;
        }

        if (auto owner = check_owner(session->barrier); !owner) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::OwnershipLost,
                std::move(owner.error().cause),
                result);
            cleanup_temp_files();
            break;
        }

        if (auto writers = check_writers(storage, session->layout, Failure::OwnershipLost); !writers) {
            quarantine_failure = commit_quarantine_failure(
                writers.error().code == Failure::WriterPresent
                    ? QuarantineFailure::WriterPresent
                    : QuarantineFailure::OwnershipLost,
                std::move(writers.error().cause),
                result);
            cleanup_temp_files();
            break;
        }

        auto ref_opt = history_storage::parse_commit_object(session->layout, candidate.identifier);
        if (!ref_opt) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::CandidateInvalid,
                Error{.code = ErrorCode::IntegrityFailure,
                      .detail = "candidate identifier cannot be parsed as a commit variant",
                      .object_identifier = candidate.identifier},
                result);
            cleanup_temp_files();
            break;
        }
        const auto& ref = *ref_opt;

        const std::string payload_path = quarantine_payload_object(
            session->layout.quarantine_prefix, ref.commit_id, ref.ciphertext_id);
        const std::string record_path = quarantine_record_object(
            session->layout.quarantine_prefix, ref.commit_id, ref.ciphertext_id);

        auto orig_pres = transport::presence(storage, candidate.identifier);
        if (!orig_pres) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::Observation,
                transport_error(orig_pres.error(), candidate.identifier),
                result);
            cleanup_temp_files();
            break;
        }

        if (*orig_pres == transport::Presence::Absent) {
            ++result.already_absent;
            cleanup_temp_files();
            continue;
        }

        auto dl = history_storage::detail::download(storage, candidate.identifier, candidate_ciphertext_path);
        if (!dl) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::Observation,
                history_storage_error(dl.error()),
                result);
            cleanup_temp_files();
            break;
        }

        auto size_valid = history_storage::detail::validate_ciphertext_size(candidate_ciphertext_path);
        if (!size_valid) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::CandidateInvalid,
                history_storage_error(size_valid.error()),
                result);
            cleanup_temp_files();
            break;
        }

        auto matches = history_storage::detail::ciphertext_matches(candidate_ciphertext_path, ref.ciphertext_id);
        if (!matches || !*matches) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::CandidateInvalid,
                matches ? Error{.code = ErrorCode::IntegrityFailure,
                                .detail = "candidate ciphertext hash does not match reference",
                                .object_identifier = candidate.identifier}
                        : history_storage_error(matches.error()),
                result);
            cleanup_temp_files();
            break;
        }

        if (!crypto::decrypt_file(candidate_ciphertext_path, candidate_plaintext_path, key, crypto::FilePurpose::History)) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::CandidateInvalid,
                Error{.code = ErrorCode::IntegrityFailure,
                      .detail = "failed to decrypt candidate commit ciphertext",
                      .object_identifier = candidate.identifier},
                result);
            cleanup_temp_files();
            break;
        }

        auto plain_bytes = history_storage::detail::read_file(candidate_plaintext_path, history::maximum_commit_plaintext_size);
        history_storage::detail::remove_file(candidate_plaintext_path);
        if (!plain_bytes) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::CandidateInvalid,
                history_storage_error(plain_bytes.error()),
                result);
            cleanup_temp_files();
            break;
        }

        auto commit = history::deserialize(*plain_bytes);
        if (!commit) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::CandidateInvalid,
                Error{.code = ErrorCode::IntegrityFailure,
                      .detail = "candidate plaintext does not deserialize to a commit",
                      .object_identifier = candidate.identifier},
                result);
            cleanup_temp_files();
            break;
        }

        auto canonical = history::serialize(*commit);
        if (!canonical || *canonical != *plain_bytes || crypto::commit_identifier(key, *canonical) != ref.commit_id) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::CandidateInvalid,
                Error{.code = ErrorCode::IntegrityFailure,
                      .detail = "candidate commit id or canonical serialization does not match reference",
                      .object_identifier = candidate.identifier},
                result);
            cleanup_temp_files();
            break;
        }

        std::error_code cipher_ec;
        const auto original_size = std::filesystem::file_size(candidate_ciphertext_path, cipher_ec);
        if (cipher_ec) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::CandidateInvalid,
                Error{.code = ErrorCode::WorkspaceFailure,
                      .detail = "could not determine candidate ciphertext file size",
                      .object_identifier = candidate.identifier},
                result);
            cleanup_temp_files();
            break;
        }

        auto sha256_res = crypto::physical::hash_file(candidate_ciphertext_path, "sha256");
        if (!sha256_res) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::CandidateInvalid,
                Error{.code = ErrorCode::IntegrityFailure,
                      .detail = "could not calculate sha256 of candidate ciphertext",
                      .object_identifier = candidate.identifier},
                result);
            cleanup_temp_files();
            break;
        }
        const auto original_sha256 = *sha256_res;

        auto record_pres = transport::presence(storage, record_path);
        if (!record_pres) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::Observation,
                transport_error(record_pres.error(), record_path),
                result);
            cleanup_temp_files();
            break;
        }

        bool preexisting_record_valid = false;
        if (*record_pres == transport::Presence::Present) {
            auto rec_dl = history_storage::detail::download(storage, record_path, readback_record_path);
            if (!rec_dl) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::MetadataVerificationFailed,
                    history_storage_error(rec_dl.error()),
                    result);
                cleanup_temp_files();
                break;
            }
            auto raw_meta = history_storage::detail::read_file(readback_record_path, 4096);
            if (!raw_meta) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::MetadataVerificationFailed,
                    history_storage_error(raw_meta.error()),
                    result);
                cleanup_temp_files();
                break;
            }
            auto decoded_rec = decode_quarantine_record(*raw_meta, key, session->layout.history_prefix);
            if (!decoded_rec) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::MetadataVerificationFailed,
                    Error{.code = ErrorCode::IntegrityFailure,
                          .detail = "preexisting quarantine record could not be decoded/authenticated",
                          .object_identifier = record_path},
                    result);
                cleanup_temp_files();
                break;
            }
            if (decoded_rec->commit_id != ref.commit_id ||
                decoded_rec->ciphertext_id != ref.ciphertext_id ||
                decoded_rec->original_identifier != candidate.identifier ||
                decoded_rec->quarantined_payload_identifier != payload_path ||
                decoded_rec->ciphertext_size_bytes != original_size ||
                decoded_rec->ciphertext_sha256 != original_sha256 ||
                !validate_quarantine_record_layout(*decoded_rec, session->layout)) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::MetadataVerificationFailed,
                    Error{.code = ErrorCode::IntegrityFailure,
                          .detail = "preexisting quarantine record fields do not match candidate",
                          .object_identifier = record_path},
                    result);
                cleanup_temp_files();
                break;
            }
            preexisting_record_valid = true;
        }

        auto payload_pres = transport::presence(storage, payload_path);
        if (!payload_pres) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::Observation,
                transport_error(payload_pres.error(), payload_path),
                result);
            cleanup_temp_files();
            break;
        }

        bool payload_verified = false;
        if (*payload_pres == transport::Presence::Present) {
            auto pay_dl = history_storage::detail::download(storage, payload_path, readback_payload_path);
            if (!pay_dl) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::PayloadVerificationFailed,
                    history_storage_error(pay_dl.error()),
                    result);
                cleanup_temp_files();
                break;
            }
            std::error_code ec;
            auto existing_size = std::filesystem::file_size(readback_payload_path, ec);
            auto existing_sha = crypto::physical::hash_file(readback_payload_path, "sha256");
            auto existing_blake = history_storage::detail::ciphertext_matches(readback_payload_path, ref.ciphertext_id);
            if (ec || existing_size != original_size ||
                !existing_sha || *existing_sha != original_sha256 ||
                !existing_blake || !*existing_blake) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::PayloadCopyFailed,
                    Error{.code = ErrorCode::IntegrityFailure,
                          .detail = "destination quarantine payload exists with different content",
                          .object_identifier = payload_path},
                    result);
                cleanup_temp_files();
                break;
            }
            payload_verified = true;
            ++result.payloads_verified;
        }

        if (!payload_verified) {
            if (platform::cancellation::requested()) {
                quarantine_failure = commit_quarantine_cancelled(result);
                cleanup_temp_files();
                break;
            }

            bool preserved = false;
            if (storage.storage.copy != nullptr) {
                auto copy_res = storage.storage.copy(storage.state.get(), candidate.identifier, payload_path);
                if (copy_res.has_value()) {
                    preserved = true;
                } else if (copy_res.error().code != transport::ErrorCode::Unsupported) {
                    auto cause = transport_error(copy_res.error(), payload_path);
                    if (platform::cancellation::requested()) {
                        quarantine_failure = commit_quarantine_failure(
                            QuarantineFailure::Cancelled,
                            std::move(cause),
                            result,
                            true);
                    } else {
                        quarantine_failure = commit_quarantine_failure(
                            QuarantineFailure::PayloadCopyFailed,
                            std::move(cause),
                            result,
                            true);
                    }
                    cleanup_temp_files();
                    break;
                }
            }

            if (!preserved) {
                auto put_res = storage.storage.put(storage.state.get(), candidate_ciphertext_path, payload_path);
                if (!put_res.has_value()) {
                    auto cause = transport_error(put_res.error(), payload_path);
                    if (platform::cancellation::requested()) {
                        quarantine_failure = commit_quarantine_failure(
                            QuarantineFailure::Cancelled,
                            std::move(cause),
                            result,
                            true);
                    } else {
                        quarantine_failure = commit_quarantine_failure(
                            QuarantineFailure::PayloadCopyFailed,
                            std::move(cause),
                            result,
                            true);
                    }
                    cleanup_temp_files();
                    break;
                }
            }

            auto pay_dl = history_storage::detail::download(storage, payload_path, readback_payload_path);
            if (!pay_dl) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::PayloadVerificationFailed,
                    history_storage_error(pay_dl.error()),
                    result);
                cleanup_temp_files();
                break;
            }
            std::error_code ec;
            auto verified_size = std::filesystem::file_size(readback_payload_path, ec);
            auto verified_sha = crypto::physical::hash_file(readback_payload_path, "sha256");
            auto verified_blake = history_storage::detail::ciphertext_matches(readback_payload_path, ref.ciphertext_id);
            if (ec || verified_size != original_size ||
                !verified_sha || *verified_sha != original_sha256 ||
                !verified_blake || !*verified_blake) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::PayloadVerificationFailed,
                    Error{.code = ErrorCode::IntegrityFailure,
                          .detail = "readback of quarantine payload failed verification",
                          .object_identifier = payload_path},
                    result);
                cleanup_temp_files();
                break;
            }
            ++result.payloads_verified;
        }

        if (preexisting_record_valid) {
            ++result.records_confirmed;
        } else {
            if (platform::cancellation::requested()) {
                quarantine_failure = commit_quarantine_cancelled(result);
                cleanup_temp_files();
                break;
            }

            if (auto owner = check_owner(session->barrier); !owner) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::OwnershipLost,
                    std::move(owner.error().cause),
                    result);
                cleanup_temp_files();
                break;
            }

            if (auto writers = check_writers(storage, session->layout, Failure::OwnershipLost); !writers) {
                quarantine_failure = commit_quarantine_failure(
                    writers.error().code == Failure::WriterPresent
                        ? QuarantineFailure::WriterPresent
                        : QuarantineFailure::OwnershipLost,
                    std::move(writers.error().cause),
                    result);
                cleanup_temp_files();
                break;
            }

            const auto now_timestamp = static_cast<std::uint64_t>(
                std::max<std::int64_t>(0, std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()));

            const QuarantineRecord record{
                .format_version = quarantine_format_version_1,
                .candidate_type = QuarantineCandidateType::CommitVariant,
                .original_identifier = candidate.identifier,
                .quarantined_payload_identifier = payload_path,
                .commit_id = ref.commit_id,
                .ciphertext_id = ref.ciphertext_id,
                .ciphertext_size_bytes = original_size,
                .ciphertext_sha256 = original_sha256,
                .quarantined_timestamp = now_timestamp,
            };

            auto enc = encode_quarantine_record(record, key, session->layout.history_prefix);
            if (!enc) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::MetadataPublicationFailed,
                    Error{.code = ErrorCode::IntegrityFailure,
                          .detail = "failed to encode quarantine record: " + enc.error(),
                          .object_identifier = record_path},
                    result);
                cleanup_temp_files();
                break;
            }

            auto wr = history_storage::detail::write_file(local_record_path, *enc);
            if (!wr) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::MetadataPublicationFailed,
                    history_storage_error(wr.error()),
                    result);
                cleanup_temp_files();
                break;
            }

            if (platform::cancellation::requested()) {
                quarantine_failure = commit_quarantine_cancelled(result);
                cleanup_temp_files();
                break;
            }

            auto put_rec = storage.storage.put(storage.state.get(), local_record_path, record_path);
            if (!put_rec.has_value()) {
                auto cause = transport_error(put_rec.error(), record_path);
                if (platform::cancellation::requested()) {
                    quarantine_failure = commit_quarantine_failure(
                        QuarantineFailure::Cancelled,
                        std::move(cause),
                        result,
                        true);
                } else {
                    quarantine_failure = commit_quarantine_failure(
                        QuarantineFailure::MetadataPublicationFailed,
                        std::move(cause),
                        result,
                        true);
                }
                cleanup_temp_files();
                break;
            }

            history_storage::detail::remove_file(readback_record_path);
            auto rec_dl = history_storage::detail::download(storage, record_path, readback_record_path);
            if (!rec_dl) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::MetadataVerificationFailed,
                    history_storage_error(rec_dl.error()),
                    result);
                cleanup_temp_files();
                break;
            }

            auto raw_meta = history_storage::detail::read_file(readback_record_path, 4096);
            if (!raw_meta) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::MetadataVerificationFailed,
                    history_storage_error(raw_meta.error()),
                    result);
                cleanup_temp_files();
                break;
            }

            auto decoded_rec = decode_quarantine_record(*raw_meta, key, session->layout.history_prefix);
            if (!decoded_rec || *decoded_rec != record || !validate_quarantine_record_layout(*decoded_rec, session->layout)) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::MetadataVerificationFailed,
                    Error{.code = ErrorCode::IntegrityFailure,
                          .detail = "readback quarantine record verification failed",
                          .object_identifier = record_path},
                    result);
                cleanup_temp_files();
                break;
            }

            ++result.records_confirmed;
        }

        if (platform::cancellation::requested()) {
            quarantine_failure = commit_quarantine_cancelled(result);
            cleanup_temp_files();
            break;
        }

        if (auto owner = check_owner(session->barrier); !owner) {
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::OwnershipLost,
                std::move(owner.error().cause),
                result);
            cleanup_temp_files();
            break;
        }

        if (auto writers = check_writers(storage, session->layout, Failure::OwnershipLost); !writers) {
            quarantine_failure = commit_quarantine_failure(
                writers.error().code == Failure::WriterPresent
                    ? QuarantineFailure::WriterPresent
                    : QuarantineFailure::OwnershipLost,
                std::move(writers.error().cause),
                result);
            cleanup_temp_files();
            break;
        }

        if (platform::cancellation::requested()) {
            quarantine_failure = commit_quarantine_cancelled(result);
            cleanup_temp_files();
            break;
        }

        auto rem = storage.storage.remove(storage.state.get(), candidate.identifier);
        if (rem.has_value()) {
            if (*rem == transport::Removal::Removed) {
                ++result.originals_removed;
                ++result.quarantined;
            } else if (*rem == transport::Removal::AlreadyAbsent) {
                ++result.already_absent;
                ++result.quarantined;
            }
        } else {
            auto primary_cause = transport_error(rem.error(), candidate.identifier);
            if (platform::cancellation::requested()) {
                quarantine_failure = commit_quarantine_failure(
                    QuarantineFailure::Cancelled,
                    std::move(primary_cause),
                    result,
                    true);
                cleanup_temp_files();
                break;
            }
            quarantine_failure = commit_quarantine_failure(
                QuarantineFailure::OriginalRemovalFailed,
                std::move(primary_cause),
                result,
                true);
            cleanup_temp_files();
            break;
        }

        cleanup_temp_files();
    }

    if (!quarantine_failure && platform::cancellation::requested()) {
        quarantine_failure = commit_quarantine_cancelled(result);
    }

    auto cleanup = release_barrier(session->barrier);
    if (quarantine_failure) {
        if (!cleanup) {
            quarantine_failure->cleanup_error = std::move(cleanup.error());
        }
        return std::unexpected(std::move(*quarantine_failure));
    }

    if (!cleanup) {
        return std::unexpected(commit_quarantine_failure(
            QuarantineFailure::BarrierRelease,
            std::move(cleanup.error()),
            result));
    }

    if (platform::cancellation::requested()) {
        return std::unexpected(commit_quarantine_cancelled(result));
    }

    return result;
}

} // namespace kasumi::application::integrity
