#include "application/sync/journal.hpp"

#include "application/history_storage/publication.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/transaction/codec.hpp"
#include "core/wire.hpp"
#include "crypto/secure_memory.hpp"
#include "journal_fault_test.hpp"
#include "platform/durability.hpp"
#include "platform/file_fingerprint.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "platform/workspace.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <sys/stat.h>
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <limits>
#include <monocypher.h>
#include <mutex>
#include <new>
#include <system_error>
#include <utility>
#include <vector>

namespace kasumi::application::sync::journal {

namespace {

struct SessionGuard {
    Session* session;
    bool keep = false;
    ~SessionGuard() {
        if (!keep && session) {
            invalidate_session(*session);
        }
    }
};

inline constexpr std::array<std::uint8_t, 4> journal_magic{'K', 'T', 'X', '3'};
inline constexpr std::array<std::uint8_t, 4> journal_log_magic{
    'K', 'T', 'D', '3'};
inline constexpr std::size_t nonce_size = crypto::NONCE_SIZE;
inline constexpr std::size_t mac_size = crypto::MAC_SIZE;
inline constexpr std::size_t aad_size =
    journal_magic.size() + sizeof(std::uint64_t);
inline constexpr std::size_t header_size = aad_size + nonce_size + mac_size;

inline constexpr std::size_t log_seq_size = sizeof(std::uint64_t);
inline constexpr std::size_t log_prev_hash_size = kasumi::HASH_SIZE;
inline constexpr std::size_t log_payload_size_field = sizeof(std::uint32_t);
inline constexpr std::size_t log_header_size =
    journal_log_magic.size() + log_seq_size + log_prev_hash_size +
    log_payload_size_field + nonce_size +
    mac_size; // 4 + 8 + 32 + 4 + 24 + 16 = 88 bytes

enum DeltaFlag : std::uint8_t {
    HasPhase = 0x01,
    HasProgress = 0x02,
    HasPublication = 0x04,
    HasEpoch = 0x08,
    HasPendingPaths = 0x10,
};

// Public calls serialize; the Coordinator's profile lock owns process
// exclusion.
std::mutex journal_mutex;
inline constexpr std::uint64_t maximum_log_size = 128ULL * 1024ULL * 1024ULL;

// Passive inspection validates and reads artifacts but must never harden
// permissions or otherwise rewrite them.
thread_local bool passive_inspection = false;

struct PassiveInspectionScope {
    PassiveInspectionScope()
        : previous(std::exchange(passive_inspection, true)) {
    }
    ~PassiveInspectionScope() {
        passive_inspection = previous;
    }
    PassiveInspectionScope(const PassiveInspectionScope&) = delete;
    PassiveInspectionScope& operator=(const PassiveInspectionScope&) = delete;
    bool previous;
};
inline constexpr std::uint64_t maximum_delta_count = 1'000'000;
inline constexpr std::size_t maximum_pending_path_count = 1'000'000;

bool path_not_found(const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory;
}

std::expected<void, std::string> validate_paths(const Paths& paths) {
    if (paths.final_path.empty() || paths.temporary_path.empty() ||
        paths.log_path.empty()) {
        return std::unexpected("journal paths cannot be empty");
    }

    const auto final_parent = paths.final_path.parent_path().lexically_normal();
    const auto temporary_parent =
        paths.temporary_path.parent_path().lexically_normal();
    const auto log_parent = paths.log_path.parent_path().lexically_normal();
    if (final_parent.empty() || final_parent.filename() != journal_file_name ||
        final_parent != temporary_parent || final_parent != log_parent) {
        return std::unexpected("journal paths must share parent directory");
    }
    if (platform::path::to_logical_utf8(paths.final_path.filename()) !=
            "snapshot.enc" ||
        platform::path::to_logical_utf8(paths.temporary_path.filename()) !=
            std::string{"snapshot.enc"} + std::string{temporary_suffix} ||
        platform::path::to_logical_utf8(paths.log_path.filename()) !=
            journal_log_file_name) {
        return std::unexpected("journal file names are invalid");
    }

    const auto final_relative =
        paths.final_path.lexically_normal().lexically_relative(final_parent);
    const auto temporary_relative =
        paths.temporary_path.lexically_normal().lexically_relative(
            final_parent);
    const auto log_relative =
        paths.log_path.lexically_normal().lexically_relative(final_parent);
    if (final_relative.empty() || temporary_relative.empty() ||
        log_relative.empty() || final_relative.has_parent_path() ||
        temporary_relative.has_parent_path() ||
        log_relative.has_parent_path()) {
        return std::unexpected(
            "journal files are not directly in parent directory");
    }
    return {};
}

std::expected<std::filesystem::file_status, std::string>
read_status(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (path_not_found(error)) {
        return std::filesystem::file_status{
            std::filesystem::file_type::not_found};
    }

    if (error) {
        return std::unexpected("could not query '" +
                               platform::path::to_utf8(path) +
                               "': " + error.message());
    }
    return status;
}

bool missing(std::filesystem::file_status status) noexcept {
    return status.type() == std::filesystem::file_type::not_found;
}

std::expected<void, std::string>
validate_parent_directory(const std::filesystem::path& path,
                          bool allow_missing) {
    const auto parent = path.parent_path();
    auto status = read_status(parent);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status) && allow_missing) {
        return {};
    }
    if (std::filesystem::is_regular_file(*status) &&
        parent.filename() == journal_file_name)
        return std::unexpected(
            "incompatible journal storage layout: private directory required");
    if (std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_directory(*status)) {
        return std::unexpected("journal parent directory is invalid");
    }
    if (passive_inspection) {
        return {};
    }
    return platform::private_storage::protect_directory(parent);
}

std::expected<void, std::string>
validate_file_or_absent(const std::filesystem::path& path,
                        std::string_view label) {
    auto status = read_status(path);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status)) {
        return {};
    }
    if (std::filesystem::is_symlink(*status) ||
        std::filesystem::is_directory(*status) ||
        !std::filesystem::is_regular_file(*status)) {
        return std::unexpected(std::string{label} +
                               " must be a regular file or absent");
    }
    if (passive_inspection) {
        return {};
    }
    return platform::private_storage::protect_file(path);
}

std::expected<void, std::string> validate_save_paths(const Paths& paths) {
    if (auto structural = validate_paths(paths); !structural) {
        return structural;
    }
    if (auto parent = validate_parent_directory(paths.final_path, false);
        !parent) {
        return parent;
    }
    for (const auto& [path, label] :
         std::array<std::pair<const std::filesystem::path&, std::string_view>,
                    3>{{{paths.final_path, "final journal"},
                        {paths.temporary_path, "temporary journal"},
                        {paths.log_path, "journal log"}}}) {
        if (auto ok = validate_file_or_absent(path, label); !ok) {
            return ok;
        }
    }
    return {};
}

std::expected<void, std::string>
validate_record_semantics(const transaction::Record& record,
                          bool validated = false) {
    if (!validated && !transaction::valid(record)) {
        return std::unexpected("invalid transactional record");
    }
    if (!record.publication_required) {
        if (record.phase == transaction::Phase::CommitPrepared ||
            record.phase == transaction::Phase::CommitUploaded ||
            record.phase == transaction::Phase::CommitVerified ||
            record.phase == transaction::Phase::HeadPublished ||
            record.phase == transaction::Phase::HeadVerified ||
            record.phase == transaction::Phase::EpochPrepared ||
            record.phase == transaction::Phase::EpochUploaded ||
            record.phase == transaction::Phase::EpochVerified) {
            return std::unexpected(
                "invalid publication phase for local-only journal");
        }
        return {};
    }
    if (record.phase < transaction::Phase::CommitUploaded) {
        return {};
    }
    const history_storage::HeadReference reference{
        .commit_id = record.commit_id, .ciphertext_id = record.ciphertext_id};
    const auto expected_stem =
        reference.commit_id + "-" + reference.ciphertext_id;
    const bool is_prefixed_marker =
        record.marker_id.ends_with(expected_stem) &&
        record.marker_id.size() > expected_stem.size() &&
        record.marker_id[record.marker_id.size() - expected_stem.size() - 1] ==
            '/' &&
        record.marker_id.find("..") == std::string::npos;
    if (!is_prefixed_marker) {
        return std::unexpected("marker ID incompatible with publication");
    }
    return {};
}

bool same_progress(const transaction::OperationProgress& a,
                   const transaction::OperationProgress& b) noexcept {
    return a.state == b.state && a.backup_slot == b.backup_slot &&
           a.had_original == b.had_original &&
           a.previous_hash == b.previous_hash;
}

std::uint8_t compute_delta_flags(const transaction::Record& prev,
                                 const transaction::Record& curr,
                                 std::vector<std::uint32_t>& changed_progress) {
    std::uint8_t flags = 0;
    if (curr.phase != prev.phase)
        flags |= HasPhase;
    for (std::size_t i = 0;
         i < curr.progress.size() && i < prev.progress.size();
         ++i) {
        if (!same_progress(curr.progress[i], prev.progress[i]))
            changed_progress.push_back(static_cast<std::uint32_t>(i));
    }
    if (!changed_progress.empty())
        flags |= HasProgress;
    if (curr.commit_id != prev.commit_id ||
        curr.ciphertext_id != prev.ciphertext_id ||
        curr.marker_id != prev.marker_id || curr.parent_ids != prev.parent_ids)
        flags |= HasPublication;
    if (curr.epoch_vault_id != prev.epoch_vault_id ||
        curr.epoch_id != prev.epoch_id ||
        curr.epoch_issued_at != prev.epoch_issued_at ||
        curr.epoch_min_history_depth != prev.epoch_min_history_depth ||
        curr.epoch_min_history_age_hours != prev.epoch_min_history_age_hours)
        flags |= HasEpoch;
    if (curr.observed_pending_paths != prev.observed_pending_paths ||
        curr.pending_paths != prev.pending_paths)
        flags |= HasPendingPaths;
    return flags;
}

void assign_mutable_fields(transaction::Record& dst,
                           const transaction::Record& src) {
    dst.phase = src.phase;
    dst.progress = src.progress;
    dst.commit_id = src.commit_id;
    dst.ciphertext_id = src.ciphertext_id;
    dst.marker_id = src.marker_id;
    dst.parent_ids = src.parent_ids;
    dst.epoch_vault_id = src.epoch_vault_id;
    dst.epoch_id = src.epoch_id;
    dst.epoch_issued_at = src.epoch_issued_at;
    dst.epoch_min_history_depth = src.epoch_min_history_depth;
    dst.epoch_min_history_age_hours = src.epoch_min_history_age_hours;
    dst.observed_pending_paths = src.observed_pending_paths;
    dst.pending_paths = src.pending_paths;
}

std::expected<std::uint32_t, std::string>
validate_log_entry_header(std::span<const std::uint8_t> bytes,
                          std::size_t offset,
                          std::size_t limit,
                          std::uint64_t count,
                          const Hash& chain) {
    if (limit - offset < log_header_size) {
        return std::unexpected("journal delta header truncated");
    }
    const auto* ptr = bytes.data() + offset;
    if (!std::equal(journal_log_magic.begin(), journal_log_magic.end(), ptr)) {
        return std::unexpected("incompatible journal delta format");
    }
    if (count >= maximum_delta_count ||
        wire::decode_le<std::uint64_t>(ptr + 4) != count ||
        std::memcmp(chain.data(), ptr + 12, 32) != 0) {
        return std::unexpected("journal delta sequence or chain mismatch");
    }
    const auto payload_size = wire::decode_le<std::uint32_t>(ptr + 44);
    if (payload_size > maximum_payload_size ||
        payload_size > limit - offset - log_header_size) {
        return std::unexpected("invalid or truncated journal delta payload");
    }
    return payload_size;
}

std::vector<std::byte>
encode_delta(std::uint8_t flags,
             const transaction::Record& record,
             std::span<const std::uint32_t> changed_progress) {
    wire::Writer writer;
    wire::write<std::uint8_t>(writer, flags);
    if (flags & HasPhase) {
        wire::write<std::uint8_t>(writer,
                                  static_cast<std::uint8_t>(record.phase));
    }
    if (flags & HasProgress) {
        wire::write<std::uint32_t>(
            writer, static_cast<std::uint32_t>(changed_progress.size()));
        for (const auto idx : changed_progress) {
            const auto& prog = record.progress[idx];
            wire::write<std::uint32_t>(writer, idx);
            wire::write<std::uint8_t>(writer,
                                      static_cast<std::uint8_t>(prog.state));
            wire::write<std::uint32_t>(writer, prog.backup_slot);
            wire::write<std::uint8_t>(writer, prog.had_original ? 1 : 0);
            wire::write_string(writer, prog.previous_hash);
        }
    }
    if (flags & HasPublication) {
        wire::write_string(writer, record.commit_id);
        wire::write_string(writer, record.ciphertext_id);
        wire::write_string(writer, record.marker_id);
        wire::write_strings(writer, record.parent_ids);
    }
    if (flags & HasEpoch) {
        wire::write_string(writer, record.epoch_vault_id);
        wire::write_string(writer, record.epoch_id);
        wire::write<std::int64_t>(writer, record.epoch_issued_at);
        wire::write<std::uint32_t>(writer, record.epoch_min_history_depth);
        wire::write<std::uint32_t>(writer, record.epoch_min_history_age_hours);
    }
    if (flags & HasPendingPaths) {
        wire::write_strings(writer, record.observed_pending_paths);
        wire::write_strings(writer, record.pending_paths);
    }
    return std::move(writer.buffer);
}

std::expected<void, std::string> apply_delta(transaction::Record& record,
                                             std::span<const std::byte> data) {
    wire::Reader reader{data};
    auto flags_raw = wire::read<std::uint8_t>(reader);
    if (!flags_raw) {
        return std::unexpected("truncated delta flags");
    }
    const auto flags = *flags_raw;
    if (flags == 0 || (flags & ~std::uint8_t{0x1f}) != 0) {
        return std::unexpected("unknown or empty delta flags");
    }
    if (flags & HasPhase) {
        auto ph = wire::read<std::uint8_t>(reader);
        if (!ph || !transaction::valid(static_cast<transaction::Phase>(*ph))) {
            return std::unexpected("invalid or truncated phase in delta");
        }
        record.phase = static_cast<transaction::Phase>(*ph);
    }
    if (flags & HasProgress) {
        auto count = wire::read<std::uint32_t>(reader);
        if (!count || *count == 0 || *count > record.progress.size()) {
            return std::unexpected("invalid progress count in delta");
        }
        std::uint32_t previous_index = 0;
        for (std::uint32_t i = 0; i < *count; ++i) {
            auto idx = wire::read<std::uint32_t>(reader);
            auto st = wire::read<std::uint8_t>(reader);
            auto slot = wire::read<std::uint32_t>(reader);
            auto had_orig = wire::read<std::uint8_t>(reader);
            auto prev_h = wire::read_string(reader, 4096);
            if (!idx || !st || !slot || !had_orig || !prev_h) {
                return std::unexpected("truncated progress item in delta");
            }
            if (*idx >= record.progress.size() ||
                (i != 0 && *idx <= previous_index)) {
                return std::unexpected("progress index out of bounds in delta");
            }
            if (!transaction::valid(
                    static_cast<transaction::OperationState>(*st))) {
                return std::unexpected("invalid progress state in delta");
            }
            if (*had_orig > 1) {
                return std::unexpected("invalid boolean in delta progress");
            }
            previous_index = *idx;
            if (*slot != record.progress[*idx].backup_slot) {
                return std::unexpected("delta changed immutable backup slot");
            }
            record.progress[*idx] = transaction::OperationProgress{
                .previous_hash = std::move(*prev_h),
                .backup_slot = *slot,
                .state = static_cast<transaction::OperationState>(*st),
                .had_original = *had_orig == 1,
            };
        }
    }
    if (flags & HasPublication) {
        auto commit_id = wire::read_string(reader, 4096);
        auto ciphertext_id = wire::read_string(reader, 4096);
        auto marker_id = wire::read_string(reader, 4096);
        std::vector<std::string> parent_ids;
        if (!commit_id || !ciphertext_id || !marker_id ||
            !wire::read_strings(
                reader, parent_ids, history::maximum_parent_count)) {
            return std::unexpected("truncated publication fields in delta");
        }
        record.commit_id = std::move(*commit_id);
        record.ciphertext_id = std::move(*ciphertext_id);
        record.marker_id = std::move(*marker_id);
        record.parent_ids = std::move(parent_ids);
    }
    if (flags & HasEpoch) {
        auto vault_id = wire::read_string(reader, 4096);
        auto epoch_id = wire::read_string(reader, 4096);
        auto issued_at = wire::read<std::int64_t>(reader);
        auto depth = wire::read<std::uint32_t>(reader);
        auto age = wire::read<std::uint32_t>(reader);
        if (!vault_id || !epoch_id || !issued_at || !depth || !age) {
            return std::unexpected("truncated epoch fields in delta");
        }
        record.epoch_vault_id = std::move(*vault_id);
        record.epoch_id = std::move(*epoch_id);
        record.epoch_issued_at = *issued_at;
        record.epoch_min_history_depth = *depth;
        record.epoch_min_history_age_hours = *age;
    }
    if (flags & HasPendingPaths) {
        if (!wire::read_strings(reader,
                                record.observed_pending_paths,
                                maximum_pending_path_count)) {
            return std::unexpected("truncated observed_pending_paths count");
        }
        if (!wire::read_strings(
                reader, record.pending_paths, maximum_pending_path_count)) {
            return std::unexpected("invalid pending_paths count");
        }
    }
    if (!reader.data.empty()) {
        return std::unexpected("trailing bytes after delta completion");
    }
    return {};
}

std::array<std::uint8_t, crypto::KEY_SIZE>
derive_log_key(const crypto::Key& journal_key) {
    std::array<std::uint8_t, crypto::KEY_SIZE> log_key{};
    crypto_blake2b_keyed(
        log_key.data(),
        log_key.size(),
        journal_key.data(),
        journal_key.size(),
        reinterpret_cast<const uint8_t*>("kasumi:journal:log:v3"),
        21);
    return log_key;
}

std::vector<std::uint8_t>
make_delta_aad(std::uint64_t seq,
               std::span<const std::byte, kasumi::HASH_SIZE> prev_hash,
               std::uint32_t payload_len,
               std::string_view operation_id) {
    std::vector<std::uint8_t> aad(48 + operation_id.size());
    std::copy(journal_log_magic.begin(), journal_log_magic.end(), aad.begin());
    wire::encode_le<std::uint64_t>(seq, aad.data() + 4);
    std::memcpy(aad.data() + 12, prev_hash.data(), kasumi::HASH_SIZE);
    wire::encode_le<std::uint32_t>(payload_len, aad.data() + 44);
    std::memcpy(aad.data() + 48, operation_id.data(), operation_id.size());
    return aad;
}

} // namespace

std::expected<Paths, std::string>
make_paths(const std::filesystem::path& profile_directory) {
    if (profile_directory.empty()) {
        return std::unexpected("profile directory cannot be empty");
    }
    for (const auto& component : profile_directory) {
        if (component == "." || component == "..") {
            return std::unexpected("profile directory cannot contain . or ..");
        }
    }

    const auto profile = profile_directory.lexically_normal();
    const auto directory =
        profile / platform::path::from_utf8(journal_file_name);
    if (directory.empty() || directory == "." || directory == "..") {
        return std::unexpected("invalid profile directory");
    }

    Paths paths{
        .final_path = directory / "snapshot.enc",
        .temporary_path = directory / platform::path::from_utf8(
                                          std::string{"snapshot.enc"} +
                                          std::string{temporary_suffix}),
        .log_path =
            directory / platform::path::from_utf8(journal_log_file_name),
    };
    auto validation = validate_paths(paths);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    return paths;
}

std::expected<transaction::Record, std::string>
create_record(std::uint64_t local_generation,
              std::uint64_t storage_generation,
              SyncPlan plan,
              bool publication_required,
              std::string observed_head_id) {
    auto id = platform::random::hex_id(transaction::transaction_id_byte_count);
    if (!id) {
        return std::unexpected(id.error());
    }
    return transaction::make_record(std::move(*id),
                                    local_generation,
                                    storage_generation,
                                    std::move(plan),
                                    publication_required,
                                    std::move(observed_head_id));
}

namespace {

// Plaintext and derived keys are wiped even when parsing or allocation throws.
struct SensitiveBytes : std::vector<std::uint8_t> {
    using std::vector<std::uint8_t>::vector;
    ~SensitiveBytes() {
        if (!empty())
            crypto_wipe(data(), size());
    }
};
struct KeyGuard {
    crypto::Key value;
    ~KeyGuard() {
        crypto_wipe(value.data(), value.size());
    }
};
struct PayloadGuard {
    std::vector<std::byte>& value;
    ~PayloadGuard() {
        if (!value.empty())
            crypto_wipe(value.data(), value.size());
    }
};
struct Tip {
    kasumi::Hash snapshot{};
    std::uint64_t bytes = 0;
    std::uint64_t count = 0;
    kasumi::Hash chain{};
    bool operator==(const Tip&) const = default;
};
struct Replay {
    transaction::Record record;
    Tip tip;
};
inline constexpr std::array<std::uint8_t, 4> tip_magic{'K', 'T', 'C', '3'};
inline constexpr std::array<std::uint8_t, 4> retirement_magic{
    'K', 'T', 'Q', '3'};
inline constexpr std::size_t tip_aad_size = 4 + 32 + 8 + 8 + 32;
inline constexpr std::size_t tip_size = tip_aad_size + nonce_size + mac_size;

std::filesystem::path tip_path(const Paths& paths) {
    return paths.final_path.parent_path() / "confirmed.enc";
}
std::filesystem::path retirement_path(const Paths& paths) {
    return paths.final_path.parent_path() / "retired.enc";
}
std::filesystem::path retired_path(const Paths& paths) {
    return paths.final_path.parent_path().parent_path() /
           "transaction.bin.enc.cleared";
}
std::expected<std::vector<std::uint8_t>, std::string>
read_bytes(const std::filesystem::path& path, std::uint64_t limit) {
    auto validated = validate_file_or_absent(path, "journal artifact");
    if (!validated)
        return std::unexpected(validated.error());
    std::error_code error;
    auto size = std::filesystem::file_size(path, error);
    if (error || size > limit || size > std::numeric_limits<std::size_t>::max())
        return std::unexpected("invalid or excessive journal artifact size");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    std::ifstream input(path, std::ios::binary);
    if (!input)
        return std::unexpected("could not open journal artifact");
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    if (input.gcount() != static_cast<std::streamsize>(bytes.size()) ||
        input.bad())
        return std::unexpected("incomplete journal artifact read");
    char extra;
    input.read(&extra, 1);
    if (input.gcount() != 0 || !input.eof() || input.bad())
        return std::unexpected("journal artifact changed during read");
    input.clear();
    input.close();
    if (input.fail())
        return std::unexpected("failed to close journal artifact");
    return bytes;
}

std::expected<void, std::string> write_file(const std::filesystem::path& path,
                                            std::span<const std::uint8_t> bytes,
                                            const transaction::Record& record,
                                            bool append,
                                            std::uint64_t index) {
    auto status = read_status(path);
    if (!status)
        return std::unexpected(status.error());
    if (missing(*status)) {
        auto created = platform::private_storage::create_file(path);
        if (!created)
            return created;
    }
    std::ofstream output(
        path, std::ios::binary | (append ? std::ios::app : std::ios::trunc));
    if (!output)
        return std::unexpected("could not open journal for writing");
    const auto first =
        append ? std::min(bytes.size(), log_header_size / 2) : bytes.size() / 2;
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(first));
#ifdef KASUMI_JOURNAL_FAULT_TESTS
    output.flush();
#endif
    journal_fault_test::hit(
        append ? "append-header" : "temporary-write", &record, index);
    const auto middle =
        append ? log_header_size + (bytes.size() - log_header_size) / 2
               : bytes.size();
    output.write(reinterpret_cast<const char*>(bytes.data() + first),
                 static_cast<std::streamsize>(middle - first));
#ifdef KASUMI_JOURNAL_FAULT_TESTS
    output.flush();
#endif
    if (append)
        journal_fault_test::hit("append-payload", &record, index);
    output.write(reinterpret_cast<const char*>(bytes.data() + middle),
                 static_cast<std::streamsize>(bytes.size() - middle));
    if (journal_fault_test::fail("write", record))
        output.setstate(std::ios::badbit);
    if (!output)
        return std::unexpected("failed to write journal");
#ifdef KASUMI_JOURNAL_FAULT_TESTS
    output.flush();
#endif
    journal_fault_test::hit(
        append ? "append-written" : "temporary-written", &record, index);
    output.flush();
    if (journal_fault_test::fail("flush", record))
        output.setstate(std::ios::badbit);
    if (!output)
        return std::unexpected("failed to flush journal");
    journal_fault_test::hit(
        append ? "append-flush" : "temporary-flush", &record, index);
    output.close();
    if (output.fail() || journal_fault_test::fail("close", record))
        return std::unexpected("failed to close journal");
    journal_fault_test::hit(
        append ? "append-close" : "temporary-close", &record, index);
    auto synced = journal_fault_test::fail("sync", record)
                      ? std::expected<void, std::string>{std::unexpected(
                            "injected sync failure")}
                      : platform::durability::sync_file(path);
    if (!synced)
        return synced;
    journal_fault_test::hit(
        append ? "append-sync" : "temporary-sync", &record, index);
    platform::perf_trace::count("journal written bytes total", bytes.size());
    return {};
}

std::expected<void, std::string>
seal_aead_frame(std::span<std::uint8_t> frame,
                std::size_t frame_aad_size,
                std::span<const std::uint8_t> aad,
                const crypto::Key& key,
                std::span<const std::byte> plaintext = {}) {
    if (auto random = platform::random::fill_bytes(
            frame.subspan(frame_aad_size, nonce_size));
        !random) {
        return random;
    }
    crypto_aead_lock(
        plaintext.empty()
            ? nullptr
            : frame.data() + frame_aad_size + nonce_size + mac_size,
        frame.data() + frame_aad_size + nonce_size,
        key.data(),
        frame.data() + frame_aad_size,
        aad.data(),
        aad.size(),
        plaintext.empty()
            ? nullptr
            : reinterpret_cast<const std::uint8_t*>(plaintext.data()),
        plaintext.size());
    return {};
}

std::expected<void, std::string>
unlock_aead_frame(const std::uint8_t* nonce_and_mac,
                  std::span<const std::uint8_t> aad,
                  const crypto::Key& key,
                  std::span<const std::uint8_t> ciphertext,
                  std::uint8_t* plaintext,
                  std::string_view error_message) {
    if (crypto_aead_unlock(plaintext,
                           nonce_and_mac + nonce_size,
                           key.data(),
                           nonce_and_mac,
                           aad.data(),
                           aad.size(),
                           ciphertext.empty() ? nullptr : ciphertext.data(),
                           ciphertext.size()) != 0)
        return std::unexpected(std::string{error_message});
    return {};
}

std::expected<void, std::string> write_tip(const Paths& paths,
                                           const Tip& tip,
                                           const transaction::Record& record,
                                           const crypto::Key& key,
                                           bool retirement = false) {
    std::array<std::uint8_t, tip_size> bytes{};
    const auto& magic = retirement ? retirement_magic : tip_magic;
    std::copy(magic.begin(), magic.end(), bytes.begin());
    std::memcpy(bytes.data() + 4, tip.snapshot.data(), 32);
    wire::encode_le<std::uint64_t>(tip.bytes, bytes.data() + 36);
    wire::encode_le<std::uint64_t>(tip.count, bytes.data() + 44);
    std::memcpy(bytes.data() + 52, tip.chain.data(), 32);
    if (auto sealed = seal_aead_frame(
            bytes, tip_aad_size, std::span{bytes}.first(tip_aad_size), key);
        !sealed)
        return sealed;
    const auto final = retirement ? retirement_path(paths) : tip_path(paths);
    auto temporary = final;
    temporary += ".new";
    auto validated =
        validate_file_or_absent(temporary, "temporary confirmation");
    if (!validated)
        return validated;
    auto written = write_file(temporary, bytes, record, false, tip.count);
    if (!written)
        return written;
    journal_fault_test::hit(retirement ? "before-retirement-proof"
                                       : "before-confirmation",
                            &record,
                            tip.count);
    auto replaced =
        journal_fault_test::fail("replace", record)
            ? std::expected<void, std::string>{std::unexpected(
                  "injected replace failure")}
            : platform::durability::replace_atomically(temporary, final);
    if (!replaced)
        return replaced;
    journal_fault_test::hit(retirement ? "after-retirement-proof"
                                       : "after-confirmation",
                            &record,
                            tip.count);
    auto synced = journal_fault_test::fail("parent-sync", record)
                      ? std::expected<void, std::string>{std::unexpected(
                            "injected parent sync failure")}
                      : platform::durability::sync_parent_directory(final);
    if (!synced)
        return synced;
    journal_fault_test::hit(
        retirement ? "retirement-proved" : "confirmed", &record, tip.count);
    if (!retirement) {
        platform::perf_trace::count("journal durable saves");
    }
    return {};
}

std::expected<Tip, std::string>
read_tip(const Paths& paths, const crypto::Key& key, bool retirement = false) {
    const auto& magic = retirement ? retirement_magic : tip_magic;
    auto bytes = read_bytes(
        retirement ? retirement_path(paths) : tip_path(paths), tip_size);
    if (!bytes)
        return std::unexpected(bytes.error());
    if (bytes->size() != tip_size ||
        !std::equal(magic.begin(), magic.end(), bytes->begin()))
        return std::unexpected("incompatible journal confirmation format");
    if (auto ok =
            unlock_aead_frame(bytes->data() + tip_aad_size,
                              std::span{*bytes}.first(tip_aad_size),
                              key,
                              {},
                              nullptr,
                              "journal confirmation authentication failed");
        !ok)
        return std::unexpected(ok.error());
    Tip tip;
    std::memcpy(tip.snapshot.data(), bytes->data() + 4, 32);
    tip.bytes = wire::decode_le<std::uint64_t>(bytes->data() + 36);
    tip.count = wire::decode_le<std::uint64_t>(bytes->data() + 44);
    std::memcpy(tip.chain.data(), bytes->data() + 52, 32);
    if (tip.bytes > maximum_log_size || tip.count > maximum_delta_count ||
        tip.count > tip.bytes / log_header_size)
        return std::unexpected("journal confirmation exceeds replay limits");
    return tip;
}

// Copy only publication metadata, never the immutable operation plan.
transaction::Record metadata_record(const transaction::Record& record,
                                    bool pending_changed) {
    return {.operation_id = record.operation_id,
            .phase = record.phase,
            .publication_required = record.publication_required,
            .observed_head_id = record.observed_head_id,
            .observed_base_id = record.observed_base_id,
            .local_generation = record.local_generation,
            .storage_generation = record.storage_generation,
            .observed_pending_paths = pending_changed
                                          ? record.observed_pending_paths
                                          : std::vector<std::string>{},
            .pending_paths = pending_changed ? record.pending_paths
                                             : std::vector<std::string>{},
            .commit_id = record.commit_id,
            .ciphertext_id = record.ciphertext_id,
            .parent_ids = record.parent_ids,
            .marker_id = record.marker_id,
            .epoch_vault_id = record.epoch_vault_id,
            .epoch_id = record.epoch_id,
            .epoch_issued_at = record.epoch_issued_at,
            .epoch_min_history_depth = record.epoch_min_history_depth,
            .epoch_min_history_age_hours = record.epoch_min_history_age_hours,
            .plan = make_sync_plan({}, record.plan.target_generation),
            .progress = {}};
}
bool same_identity(const transaction::Record& a, const transaction::Record& b) {
    if (a.operation_id != b.operation_id ||
        a.local_generation != b.local_generation ||
        a.storage_generation != b.storage_generation ||
        a.publication_required != b.publication_required ||
        a.observed_head_id != b.observed_head_id ||
        a.observed_base_id != b.observed_base_id ||
        a.plan.target_generation != b.plan.target_generation ||
        a.plan.operations.size() != b.plan.operations.size())
        return false;
    for (std::size_t i = 0; i < a.plan.operations.size(); ++i) {
        const auto& x = a.plan.operations[i];
        const auto& y = b.plan.operations[i];
        if (x.action != y.action || x.path != y.path ||
            x.alt_path != y.alt_path || x.hash != y.hash || x.size != y.size ||
            x.exclusive_destination != y.exclusive_destination ||
            x.expected_source_identity != y.expected_source_identity)
            return false;
    }
    return true;
}

// Validates every entry header up to byte_limit and matches tip count/hash.
template <typename OnEntry>
std::expected<void, std::string>
walk_log_chain(std::span<const std::uint8_t> log,
               std::size_t byte_limit,
               const Tip& expected_tip,
               std::string_view mismatch_msg,
               OnEntry&& on_entry) {
    auto chain = expected_tip.snapshot;
    std::uint64_t count = 0;
    std::size_t offset = 0;
    while (offset < byte_limit) {
        const auto size =
            validate_log_entry_header(log, offset, byte_limit, count, chain);
        if (!size)
            return std::unexpected(size.error());
        if (auto ok = on_entry(count, chain, offset, *size); !ok)
            return std::unexpected(ok.error());
        chain =
            hasher::hash_bytes(log.data() + offset, log_header_size + *size);
        offset += log_header_size + *size;
        ++count;
    }
    if (count != expected_tip.count || chain != expected_tip.chain)
        return std::unexpected(std::string{mismatch_msg});
    return {};
}

std::expected<Replay, std::string> replay(const Paths& paths,
                                          const crypto::Key& key) {
    auto tip = read_tip(paths, key);
    if (!tip)
        return std::unexpected(tip.error());
    auto snapshot =
        read_bytes(paths.final_path, header_size + maximum_payload_size);
    if (!snapshot)
        return std::unexpected(snapshot.error());
    if (snapshot->size() < header_size || !std::equal(journal_magic.begin(),
                                                      journal_magic.end(),
                                                      snapshot->begin()))
        return std::unexpected("incompatible journal snapshot format");
    if (hasher::hash_bytes(snapshot->data(), snapshot->size()) != tip->snapshot)
        return std::unexpected(
            "journal snapshot/confirmation generation mismatch");
    auto size = wire::decode_le<std::uint64_t>(snapshot->data() + 4);
    if (size != snapshot->size() - header_size || size > maximum_payload_size)
        return std::unexpected("invalid journal snapshot payload size");
    SensitiveBytes plaintext(static_cast<std::size_t>(size));
    if (auto ok = unlock_aead_frame(snapshot->data() + aad_size,
                                    std::span{*snapshot}.first(aad_size),
                                    key,
                                    std::span{*snapshot}.subspan(header_size),
                                    plaintext.data(),
                                    "journal snapshot authentication failed");
        !ok)
        return std::unexpected(ok.error());
    auto record =
        transaction::codec::decode(std::as_bytes(std::span{plaintext}));
    if (!record)
        return std::unexpected(record.error());
    auto valid_record = validate_record_semantics(*record);
    if (!valid_record)
        return std::unexpected(valid_record.error());
    auto status = read_status(paths.log_path);
    if (!status)
        return std::unexpected(status.error());
    std::vector<std::uint8_t> log;
    if (!missing(*status)) {
        auto data = read_bytes(paths.log_path, maximum_log_size);
        if (!data)
            return std::unexpected(data.error());
        log = std::move(*data);
    }
    if (log.size() < tip->bytes)
        return std::unexpected("confirmed journal suffix missing or truncated");
    KeyGuard log_key{derive_log_key(key)};
    auto walked = walk_log_chain(
        log,
        tip->bytes,
        *tip,
        "confirmed journal prefix mismatch",
        [&](std::uint64_t count,
            const kasumi::Hash& chain,
            std::size_t offset,
            std::uint32_t payload_size) -> std::expected<void, std::string> {
            const auto* ptr = log.data() + offset;
            const auto aad = make_delta_aad(
                count, chain, payload_size, record->operation_id);
            SensitiveBytes delta(payload_size);
            if (auto ok =
                    unlock_aead_frame(ptr + 48,
                                      aad,
                                      log_key.value,
                                      {ptr + log_header_size, payload_size},
                                      delta.data(),
                                      "journal delta authentication failed");
                !ok)
                return ok;
            if (auto applied =
                    apply_delta(*record, std::as_bytes(std::span{delta}));
                !applied)
                return applied;
            if (auto semantic = validate_record_semantics(metadata_record(
                    *record, (delta.front() & HasPendingPaths) != 0));
                !semantic)
                return std::unexpected(
                    "journal delta semantic validation failed: " +
                    semantic.error());
            return {};
        });
    if (!walked)
        return std::unexpected(walked.error());
    valid_record = validate_record_semantics(*record);
    if (!valid_record)
        return std::unexpected(valid_record.error());
    return Replay{std::move(*record), *tip};
}

std::expected<Tip, std::string> save_snapshot(const Paths& paths,
                                              const transaction::Record& record,
                                              const crypto::Key& key) {
    journal_fault_test::hit("before-snapshot", &record);
    auto encoded = transaction::codec::encode(record);
    if (!encoded)
        return std::unexpected(encoded.error());
    PayloadGuard encoded_guard{*encoded};
    if (encoded->size() > maximum_payload_size)
        return std::unexpected("journal snapshot exceeds limit");
    std::vector<std::uint8_t> bytes(header_size + encoded->size());
    std::copy(journal_magic.begin(), journal_magic.end(), bytes.begin());
    wire::encode_le<std::uint64_t>(encoded->size(), bytes.data() + 4);
    if (auto sealed = seal_aead_frame(
            bytes, aad_size, std::span{bytes}.first(aad_size), key, *encoded);
        !sealed)
        return std::unexpected(sealed.error());
    auto written = write_file(paths.temporary_path, bytes, record, false, 0);
    if (!written)
        return std::unexpected(written.error());
    journal_fault_test::hit("before-snapshot-replace", &record);
    auto replaced = platform::durability::replace_atomically(
        paths.temporary_path, paths.final_path);
    if (!replaced)
        return std::unexpected(replaced.error());
    journal_fault_test::hit("after-snapshot-replace", &record);
    Tip tip{.snapshot = hasher::hash_bytes(bytes.data(), bytes.size())};
    tip.chain = tip.snapshot;
    auto confirmed = write_tip(paths, tip, record, key);
    if (!confirmed)
        return std::unexpected(confirmed.error());
    auto parent = platform::durability::sync_parent_directory(
        paths.final_path.parent_path());
    if (!parent)
        return std::unexpected(parent.error());
    return tip;
}

struct ArtifactState {
    std::optional<platform::FileFingerprint> fingerprint;
    std::uint64_t bytes = 0;
};

std::expected<ArtifactState, std::string>
artifact_state(const std::filesystem::path& path) {
    auto status = read_status(path);
    if (!status)
        return std::unexpected(status.error());
    if (missing(*status))
        return ArtifactState{};
    if (std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_regular_file(*status))
        return std::unexpected(
            "journal artifact must be a physical regular file");
    std::error_code error;
    const auto bytes = std::filesystem::file_size(path, error);
    if (error)
        return std::unexpected("could not query journal artifact size");
#ifndef __linux__
    auto identity = platform::regular_file_fingerprint(path);
    if (!identity)
        return std::unexpected(identity.error());
    return ArtifactState{*identity, bytes};
#else
    struct stat native{};
    if (::lstat(path.c_str(), &native) != 0 || !S_ISREG(native.st_mode))
        return std::unexpected("could not query journal artifact identity");
    platform::FileFingerprint identity{
        .kind = platform::FileFingerprintKind::PosixFileIdentity,
        .value = {static_cast<std::uint64_t>(native.st_dev),
                  static_cast<std::uint64_t>(native.st_ino),
                  static_cast<std::uint64_t>(native.st_ctim.tv_sec),
                  static_cast<std::uint64_t>(native.st_ctim.tv_nsec)}};
    return ArtifactState{identity, bytes};
#endif
}

bool same_artifact(const std::optional<platform::FileFingerprint>& a,
                   const std::optional<platform::FileFingerprint>& b) noexcept {
    return a && b && a->kind == b->kind && a->value == b->value;
}

bool is_known_artifact_name(std::string_view name) noexcept {
    constexpr std::array<std::string_view, 7> known_names{
        "snapshot.enc",
        "snapshot.enc.new",
        "transaction.log.enc",
        "confirmed.enc",
        "confirmed.enc.new",
        "retired.enc",
        "retired.enc.new",
    };
    return std::ranges::find(known_names, name) != known_names.end();
}

std::expected<bool, std::string>
validate_artifact_directory(const std::filesystem::path& directory,
                            std::string_view file_label) {
    bool has_retired_file = false;
    std::error_code ec;
    for (const auto& entry :
         std::filesystem::directory_iterator(directory, ec)) {
        if (ec) {
            return std::unexpected("failed to enumerate journal artifacts: " +
                                   ec.message());
        }
        const auto name = entry.path().filename().string();
        if (!is_known_artifact_name(name)) {
            return std::unexpected("unknown journal artifact");
        }
        if (name == "retired.enc") {
            has_retired_file = true;
        }
        if (auto validated = validate_file_or_absent(entry.path(), file_label);
            !validated) {
            return std::unexpected(validated.error());
        }
    }
    if (ec) {
        return std::unexpected("failed to enumerate journal artifacts: " +
                               ec.message());
    }
    return has_retired_file;
}

bool is_reset_checkpoint(const transaction::Record& record) noexcept {
    return record.phase == transaction::Phase::Started &&
           std::ranges::all_of(record.progress, [](const auto& progress) {
               return progress.state == transaction::OperationState::Pending &&
                      !progress.had_original && progress.previous_hash.empty();
           });
}

kasumi::Hash journal_key_id(const KeyGuard& journal_key) {
    return hasher::hash_bytes(journal_key.value.data(),
                              journal_key.value.size());
}

std::expected<Tip, std::string> save_delta(const Paths& paths,
                                           const transaction::Record& record,
                                           const crypto::Key& key,
                                           const transaction::Record& previous,
                                           const Tip& previous_tip,
                                           SaveMode mode) {
    if (!same_identity(previous, record))
        return std::unexpected("active journal identity changed; complete "
                               "recovery/clear before a new transaction");
    const bool rollback_reset = is_reset_checkpoint(record);
    const bool local_rollback =
        mode == SaveMode::Rollback && !record.publication_required &&
        record.phase == transaction::Phase::FilesStaged &&
        previous.phase <= transaction::Phase::LocalChangesApplied;
    if (mode == SaveMode::Rollback && !rollback_reset && !local_rollback)
        return std::unexpected("invalid rollback checkpoint");
    std::vector<std::uint32_t> changed_progress;
    const auto flags = compute_delta_flags(previous, record, changed_progress);
    if (mode == SaveMode::Advance) {
        if (record.phase < previous.phase)
            return std::unexpected("checkpoint phase regressed");
        for (const auto index : changed_progress)
            if (record.progress[index].state < previous.progress[index].state)
                return std::unexpected("checkpoint progress regressed");
    }
    if (local_rollback) {
        for (const auto index : changed_progress)
            if (record.progress[index].state < previous.progress[index].state &&
                (!is_local_mutation(record.plan.operations[index].action) ||
                 record.progress[index].state !=
                     transaction::OperationState::Prepared ||
                 previous.progress[index].state <
                     transaction::OperationState::BackupCreated))
                return std::unexpected("invalid local rollback progress");
    }
    auto log_status = read_status(paths.log_path);
    if (!log_status)
        return std::unexpected(log_status.error());
    if (!missing(*log_status)) {
        std::error_code error;
        const auto size = std::filesystem::file_size(paths.log_path, error);
        if (error)
            return std::unexpected("could not query journal log size");
        if (size < previous_tip.bytes)
            return std::unexpected("confirmed journal log was truncated");
        if (size > previous_tip.bytes) {
            if (journal_fault_test::fail("rollback-truncate", record))
                return std::unexpected("injected rollback truncation failure");
            std::filesystem::resize_file(
                paths.log_path, previous_tip.bytes, error);
            if (error)
                return std::unexpected(
                    "could not truncate unconfirmed journal tail: " +
                    error.message());
            auto synced = platform::durability::sync_file(paths.log_path);
            if (!synced)
                return std::unexpected(synced.error());
        }
    }
    if (missing(*log_status) && previous_tip.bytes != 0)
        return std::unexpected("confirmed journal log is missing");
    // Re-establish durability after a prior ambiguous error, including
    // equal-state retries.
    auto snapshot_sync = platform::durability::sync_file(paths.final_path);
    if (!snapshot_sync)
        return std::unexpected(snapshot_sync.error());
    if (flags == 0) {
        if (!missing(*log_status)) {
            auto synced = platform::durability::sync_file(paths.log_path);
            if (!synced)
                return std::unexpected(synced.error());
        }
        auto synced = platform::durability::sync_file(tip_path(paths));
        if (!synced)
            return std::unexpected(synced.error());
        auto parent =
            platform::durability::sync_parent_directory(paths.final_path);
        if (!parent)
            return std::unexpected(parent.error());
        return previous_tip;
    }
    if (previous_tip.count >= maximum_delta_count)
        return std::unexpected("journal delta count exceeds limit");
    auto encoded = encode_delta(flags, record, changed_progress);
    PayloadGuard encoded_guard{encoded};
    if (encoded.size() > maximum_payload_size ||
        previous_tip.bytes > maximum_log_size ||
        log_header_size + encoded.size() >
            maximum_log_size - previous_tip.bytes)
        return std::unexpected("journal delta/log exceeds limit");
    KeyGuard log_key{derive_log_key(key)};
    const auto aad = make_delta_aad(previous_tip.count,
                                    previous_tip.chain,
                                    static_cast<std::uint32_t>(encoded.size()),
                                    record.operation_id);
    std::vector<std::uint8_t> bytes(log_header_size + encoded.size());
    std::copy_n(aad.begin(), 48, bytes.begin());
    if (auto sealed = seal_aead_frame(bytes, 48, aad, log_key.value, encoded);
        !sealed)
        return std::unexpected(sealed.error());
    auto written =
        write_file(paths.log_path, bytes, record, true, previous_tip.count);
    if (!written)
        return std::unexpected(written.error());
    auto parent = platform::durability::sync_parent_directory(paths.log_path);
    if (!parent)
        return std::unexpected(parent.error());
    auto tip = previous_tip;
    tip.bytes += bytes.size();
    ++tip.count;
    tip.chain = hasher::hash_bytes(bytes.data(), bytes.size());
    auto confirmed = write_tip(paths, tip, record, key);
    if (!confirmed)
        return std::unexpected(confirmed.error());
    return tip;
}

std::expected<void, std::string> validate_retirement(const Paths& paths,
                                                     const Tip& proof,
                                                     const crypto::Key& key) {
    for (const auto& path :
         {paths.final_path, paths.log_path, tip_path(paths)}) {
        auto status = read_status(path);
        if (!status)
            return std::unexpected(status.error());
        if (missing(*status))
            continue;
        if (path == tip_path(paths)) {
            auto tip = read_tip(paths, key);
            if (!tip)
                return std::unexpected(tip.error());
            if (*tip != proof)
                return std::unexpected(
                    "retired confirmation generation mismatch");
        } else if (path == paths.final_path) {
            auto bytes = read_bytes(path, header_size + maximum_payload_size);
            if (!bytes)
                return std::unexpected(bytes.error());
            if (hasher::hash_bytes(bytes->data(), bytes->size()) !=
                proof.snapshot)
                return std::unexpected("retired snapshot generation mismatch");
        } else {
            auto bytes = read_bytes(path, maximum_log_size);
            if (!bytes)
                return std::unexpected(bytes.error());
            if (bytes->size() != proof.bytes)
                return std::unexpected("retired log length mismatch");
            if (auto ok = walk_log_chain(
                    *bytes,
                    bytes->size(),
                    proof,
                    "retired log confirmation mismatch",
                    [](std::uint64_t,
                       const kasumi::Hash&,
                       std::size_t,
                       std::uint32_t) -> std::expected<void, std::string> {
                        return {};
                    });
                !ok)
                return std::unexpected(ok.error());
        }
    }
    return {};
}

std::expected<void, std::string> clear_locked(const Paths& paths,
                                              const crypto::Key& key) {
    auto structural = validate_paths(paths);
    if (!structural)
        return structural;
    const auto active = paths.final_path.parent_path();
    const auto retired = retired_path(paths);
    auto outer = validate_parent_directory(active, true);
    if (!outer)
        return outer;
    auto active_status = read_status(active),
         retired_status = read_status(retired);
    if (!active_status)
        return std::unexpected(active_status.error());
    if (!retired_status)
        return std::unexpected(retired_status.error());
    if (!missing(*active_status) && !missing(*retired_status))
        return std::unexpected("active and retired journals coexist");
    if (missing(*active_status) && missing(*retired_status))
        return {};
    const auto root = missing(*active_status) ? retired : active;
    auto parent = validate_parent_directory(root / "snapshot.enc", false);
    if (!parent)
        return parent;
    // Reject the whole cleanup before touching any malformed or unknown
    // artifact.
    if (auto ok = validate_artifact_directory(root, "cleanup artifact"); !ok) {
        if (ok.error() == "unknown journal artifact")
            return std::unexpected("unknown journal cleanup artifact");
        return std::unexpected(ok.error());
    }
    const Paths root_paths{root / "snapshot.enc",
                           root / "snapshot.enc.new",
                           root / "transaction.log.enc"};
    if (root == retired && !std::filesystem::is_empty(root)) {
        auto proof = read_tip(root_paths, key, true);
        if (!proof)
            return std::unexpected("retirement is not authenticated: " +
                                   proof.error());
        auto matching = validate_retirement(root_paths, *proof, key);
        if (!matching)
            return matching;
    }
    if (root == active) {
        journal_fault_test::hit("before-clear");
        if (journal_fault_test::cleanup_fail("retire"))
            return std::unexpected("injected retirement failure");
        auto previous = replay(paths, key);
        if (!previous)
            return std::unexpected(previous.error());
        const auto& record = previous->record;
        const bool reset = is_reset_checkpoint(record);
        if (record.phase != transaction::Phase::CleanupCompleted && !reset)
            return std::unexpected(
                "cannot clear a nonterminal journal before confirmed rollback");
        auto proof_status = read_status(retirement_path(paths));
        if (!proof_status)
            return std::unexpected(proof_status.error());
        if (missing(*proof_status)) {
            auto proved = write_tip(paths, previous->tip, record, key, true);
            if (!proved)
                return proved;
        } else {
            auto proof = read_tip(paths, key, true);
            if (!proof)
                return std::unexpected(proof.error());
            if (*proof != previous->tip)
                return std::unexpected("retirement proof generation mismatch");
        }
        journal_fault_test::hit("clear-authorized");
        auto retired_directory =
            platform::durability::retire_directory(active, retired);
        if (!retired_directory)
            return retired_directory;
    }
    if (journal_fault_test::cleanup_fail("cleanup-parent-sync"))
        return std::unexpected("injected cleanup parent sync failure");
    auto synced = platform::durability::sync_parent_directory(retired);
    if (!synced)
        return synced;
    journal_fault_test::hit("retired");
    if (journal_fault_test::cleanup_fail("cleanup"))
        return std::unexpected("injected cleanup failure");
    std::size_t cleanup_index = 0;
    for (const auto& entry : std::filesystem::directory_iterator(retired)) {
        if (entry.path().filename() == "retired.enc")
            continue;
        std::error_code error;
        if (!std::filesystem::remove(entry.path(), error) || error)
            return std::unexpected("could not clean retired journal: " +
                                   error.message());
        journal_fault_test::hit("cleanup-file", nullptr, cleanup_index++);
    }
    // The authenticated clear intent survives every partial deletion.
    if (journal_fault_test::cleanup_fail("cleanup-data-sync"))
        return std::unexpected("injected cleanup data sync failure");
    auto data_removed =
        platform::durability::sync_parent_directory(retired / "retired.enc");
    if (!data_removed)
        return data_removed;
    auto proof_status = read_status(retired / "retired.enc");
    if (!proof_status)
        return std::unexpected(proof_status.error());
    if (!missing(*proof_status)) {
        std::error_code proof_error;
        if (!std::filesystem::remove(retired / "retired.enc", proof_error) ||
            proof_error)
            return std::unexpected("could not remove retirement proof: " +
                                   proof_error.message());
    }
    journal_fault_test::hit("cleanup-proof-removed");
    auto proof_removed =
        platform::durability::sync_parent_directory(retired / "retired.enc");
    if (!proof_removed)
        return proof_removed;
    std::error_code error;
    if (!std::filesystem::remove(retired, error) || error)
        return std::unexpected("could not remove retired journal directory: " +
                               error.message());
    return platform::durability::sync_parent_directory(retired);
}

bool session_bound_to(const Session& session,
                      const Paths& requested,
                      const std::array<std::byte, 32>& key) noexcept {
    return session.paths.final_path == requested.final_path &&
           session.paths.temporary_path == requested.temporary_path &&
           session.paths.log_path == requested.log_path &&
           session.key_identity == key;
}

std::expected<void, std::string>
refresh_session_cache(Session& session, const Paths& paths, const Tip& tip) {
    auto snapshot = artifact_state(paths.final_path);
    auto log = artifact_state(paths.log_path);
    if (!snapshot || !log) {
        return std::unexpected(!snapshot ? snapshot.error() : log.error());
    }
    session.tip_snapshot = tip.snapshot;
    session.tip_bytes = tip.bytes;
    session.tip_count = tip.count;
    session.tip_chain = tip.chain;
    session.snapshot_fingerprint = snapshot->fingerprint;
    session.snapshot_bytes = snapshot->bytes;
    session.log_fingerprint = log->fingerprint;
    return {};
}

std::expected<void, std::string>
bind_session_cache(Session* session,
                   const Paths& paths,
                   const kasumi::Hash& key_id,
                   transaction::Record&& record,
                   const Tip& tip) {
    if (!session) {
        return {};
    }
    if (auto ok = refresh_session_cache(*session, paths, tip); !ok) {
        return ok;
    }
    session->paths = paths;
    session->operation_id = record.operation_id;
    session->key_identity = key_id;
    session->confirmed_record.emplace(std::move(record));
    session->state = SessionState::Confirmed;
    return {};
}

} // namespace

std::expected<void, std::string>
save(const Paths& paths,
     const transaction::Record& record,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
     SaveMode mode,
     Session* session) {
    std::lock_guard lock(journal_mutex);
    KeyGuard journal_key{crypto::derive_key(key, crypto::KeyPurpose::Journal)};
    try {
        if (session && session->state == SessionState::Retired)
            return std::unexpected("journal session is retired");
        SessionGuard guard{session};
        if (mode != SaveMode::Advance && mode != SaveMode::Rollback)
            return std::unexpected("unknown journal save mode");
        auto structural = validate_paths(paths);
        if (!structural)
            return structural;
        if (session && confirmed_record(*session) == &record)
            return std::unexpected(
                "requested record must be independent of the session cache");
        const auto key_id = journal_key_id(journal_key);
        if (session && is_session_valid(*session) &&
            !session_bound_to(*session, paths, key_id))
            return std::unexpected("active journal session paths/key changed");
        auto codec_validation = transaction::codec::validate(record);
        if (!codec_validation)
            return codec_validation;
        auto semantic = validate_record_semantics(record, true);
        if (!semantic)
            return semantic;
        auto retired = read_status(retired_path(paths));
        if (!retired)
            return std::unexpected(retired.error());
        auto proof = read_status(retirement_path(paths));
        if (!proof)
            return std::unexpected(proof.error());
        if (!missing(*retired) || !missing(*proof))
            return std::unexpected(
                "journal retirement must finish before saving");
        const auto bind_session =
            [&](auto make_confirmed,
                const Tip& tip) -> std::expected<void, std::string> {
            if (!session)
                return {};
            if (journal_fault_test::cleanup_fail("session-update"))
                throw std::bad_alloc{};
            return bind_session_cache(
                session, paths, key_id, make_confirmed(), tip);
        };
        if (session && is_session_valid(*session)) {
            // Check before private-storage validation updates ACL/ctime itself.
            auto snapshot = artifact_state(paths.final_path);
            auto log = artifact_state(paths.log_path);
            if (!snapshot || !log)
                return std::unexpected(!snapshot ? snapshot.error()
                                                 : log.error());
            const bool artifacts_match =
                same_artifact(snapshot->fingerprint,
                              session->snapshot_fingerprint) &&
                snapshot->bytes == session->snapshot_bytes &&
                log->bytes == session->tip_bytes &&
                (session->tip_bytes == 0
                     ? !log->fingerprint
                     : same_artifact(log->fingerprint,
                                     session->log_fingerprint));
            auto validation = validate_save_paths(paths);
            if (!validation)
                return validation;
            auto disk_tip = read_tip(paths, journal_key.value);
            if (!disk_tip)
                return std::unexpected(disk_tip.error());
            const Tip session_tip{.snapshot = session->tip_snapshot,
                                  .bytes = session->tip_bytes,
                                  .count = session->tip_count,
                                  .chain = session->tip_chain};
            if (artifacts_match && *disk_tip == session_tip) {
                auto saved_tip = save_delta(paths,
                                            record,
                                            journal_key.value,
                                            *session->confirmed_record,
                                            session_tip,
                                            mode);
                if (!saved_tip)
                    return std::unexpected(saved_tip.error());
                if (journal_fault_test::cleanup_fail("session-update"))
                    throw std::bad_alloc{};
                journal_fault_test::hit(
                    "before-session-update", &record, saved_tip->count);
                if (auto refreshed =
                        refresh_session_cache(*session, paths, *saved_tip);
                    !refreshed)
                    return refreshed;
                assign_mutable_fields(*session->confirmed_record, record);
                guard.keep = true;
                return {};
            }
            invalidate_session(*session);
        }
        auto outer =
            validate_parent_directory(paths.final_path.parent_path(), false);
        if (!outer)
            return outer;
        auto status = read_status(paths.final_path.parent_path());
        if (!status)
            return std::unexpected(status.error());
        const bool fresh = missing(*status);
        if (fresh && mode == SaveMode::Rollback)
            return std::unexpected("rollback requires active authority");
        if (fresh) {
            auto name = platform::random::hex_id();
            if (!name)
                return std::unexpected(name.error());
            const auto active = paths.final_path.parent_path();
            auto stage = platform::create_workspace_at(
                active.parent_path() / (".journal-init-" + *name));
            if (!stage)
                return std::unexpected(stage.error());
            struct StagingGuard {
                const platform::Workspace& stage;
                ~StagingGuard() noexcept {
                    try {
                        static_cast<void>(platform::remove_workspace(stage));
                    } catch (...) {
                    }
                }
            } staging_guard{*stage};
            const Paths staging_paths{stage->root / paths.final_path.filename(),
                                      stage->root /
                                          paths.temporary_path.filename(),
                                      stage->root / paths.log_path.filename()};
            auto tip = save_snapshot(staging_paths, record, journal_key.value);
            if (!tip)
                return std::unexpected(tip.error());
            if (auto installed =
                    platform::durability::retire_directory(stage->root, active);
                !installed)
                return installed;
            if (auto synced =
                    platform::durability::sync_parent_directory(active);
                !synced)
                return synced;
            if (auto bound = bind_session(
                    [&] {
                        return transaction::Record{record};
                    },
                    *tip);
                !bound)
                return bound;
            guard.keep = true;
            return {};
        }
        auto validation = validate_save_paths(paths);
        if (!validation)
            return validation;
        auto previous = replay(paths, journal_key.value);
        if (!previous)
            return std::unexpected(previous.error());
        auto saved_tip = save_delta(paths,
                                    record,
                                    journal_key.value,
                                    previous->record,
                                    previous->tip,
                                    mode);
        if (!saved_tip)
            return std::unexpected(saved_tip.error());
        if (auto bound = bind_session(
                [&] {
                    assign_mutable_fields(previous->record, record);
                    return std::move(previous->record);
                },
                *saved_tip);
            !bound)
            return bound;
        guard.keep = true;
        return {};
    } catch (const std::exception& error) {
        return std::unexpected(std::string{"failed to save journal: "} +
                               error.what());
    }
}

std::expected<std::optional<transaction::Record>, std::string>
load(const Paths& paths,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
     Session* session) {
    std::lock_guard lock(journal_mutex);
    KeyGuard journal_key{crypto::derive_key(key, crypto::KeyPurpose::Journal)};
    SessionGuard guard{session};
    const auto retire_and_clear = [&]()
        -> std::expected<std::optional<transaction::Record>, std::string> {
        auto cleared = clear_locked(paths, journal_key.value);
        if (!cleared)
            return std::unexpected(cleared.error());
        if (session) {
            const bool bound = !session_operation(*session).empty();
            invalidate_session(*session);
            session->state =
                bound ? SessionState::Retired : SessionState::Uninitialized;
            guard.keep = true;
        }
        return std::optional<transaction::Record>{};
    };
    try {
        if (session && session->state == SessionState::Retired)
            return std::unexpected("journal session is retired");
        const auto key_id = journal_key_id(journal_key);
        if (session && is_session_valid(*session) &&
            !session_bound_to(*session, paths, key_id)) {
            return std::unexpected("active journal session paths/key changed");
        }
        auto structural = validate_paths(paths);
        if (!structural)
            return std::unexpected(structural.error());
        auto retired = read_status(retired_path(paths));
        if (!retired)
            return std::unexpected(retired.error());
        if (!missing(*retired))
            return retire_and_clear();
        auto outer =
            validate_parent_directory(paths.final_path.parent_path(), true);
        if (!outer)
            return std::unexpected(outer.error());
        auto parent = validate_parent_directory(paths.final_path, true);
        if (!parent)
            return std::unexpected(parent.error());
        auto directory = read_status(paths.final_path.parent_path());
        if (!directory)
            return std::unexpected(directory.error());
        if (missing(*directory)) {
            if (session) {
                invalidate_session(*session);
                session->state = SessionState::Uninitialized;
            }
            guard.keep = true;
            return std::optional<transaction::Record>{};
        }
        auto proof = read_status(retirement_path(paths));
        if (!proof)
            return std::unexpected(proof.error());
        if (!missing(*proof))
            return retire_and_clear();
        auto loaded = replay(paths, journal_key.value);
        if (!loaded)
            return std::unexpected(loaded.error());
        journal_fault_test::hit("loaded", &loaded->record);
        if (auto bound = bind_session_cache(session,
                                            paths,
                                            key_id,
                                            transaction::Record{loaded->record},
                                            loaded->tip);
            !bound) {
            return std::unexpected(bound.error());
        }
        auto result =
            std::optional<transaction::Record>{std::move(loaded->record)};
        guard.keep = true;
        return result;
    } catch (const std::exception& error) {
        return std::unexpected(std::string{"failed to load journal: "} +
                               error.what());
    }
}

std::expected<void, std::string>
clear(const Paths& paths,
      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
      Session* session) {
    std::lock_guard lock(journal_mutex);
    KeyGuard journal_key{crypto::derive_key(key, crypto::KeyPurpose::Journal)};
    SessionGuard guard{session};
    try {
        const auto key_id = journal_key_id(journal_key);
        if (session && is_session_valid(*session) &&
            !session_bound_to(*session, paths, key_id)) {
            return std::unexpected("active journal session paths/key changed");
        }
        auto result = clear_locked(paths, journal_key.value);
        if (result && session) {
            session->state = SessionState::Retired;
        }
        return result;
    } catch (const std::exception& error) {
        return std::unexpected(std::string{"failed to clear journal: "} +
                               error.what());
    }
}

InspectionResult inspect(const Paths& paths,
                         std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    try {
        PassiveInspectionScope passive;
        std::lock_guard lock(journal_mutex);
        auto structural = validate_paths(paths);
        if (!structural) {
            return InspectionResult::Corrupted;
        }

        const auto active = paths.final_path.parent_path();
        const auto retired = retired_path(paths);

        auto active_status = read_status(active);
        auto retired_status = read_status(retired);
        if (!active_status || !retired_status) {
            return InspectionResult::Corrupted;
        }

        if (!missing(*active_status) &&
            (!std::filesystem::is_directory(*active_status) ||
             std::filesystem::is_symlink(*active_status))) {
            return InspectionResult::Corrupted;
        }
        if (!missing(*retired_status) &&
            (!std::filesystem::is_directory(*retired_status) ||
             std::filesystem::is_symlink(*retired_status))) {
            return InspectionResult::Corrupted;
        }

#if defined(_WIN32)
        const auto has_reparse = [](const std::filesystem::path& path) {
            const DWORD attrs = GetFileAttributesW(path.c_str());
            return attrs != INVALID_FILE_ATTRIBUTES &&
                   (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        };
        if ((!missing(*active_status) && has_reparse(active)) ||
            (!missing(*retired_status) && has_reparse(retired))) {
            return InspectionResult::Corrupted;
        }
#endif

        if (!missing(*active_status) && !missing(*retired_status)) {
            return InspectionResult::Corrupted;
        }

        if (missing(*active_status) && missing(*retired_status)) {
            return InspectionResult::Absent;
        }

        KeyGuard journal_key{
            crypto::derive_key(key, crypto::KeyPurpose::Journal)};

        const auto validate_retired_tip = [&](const Paths& target_paths) {
            auto proof = read_tip(target_paths, journal_key.value, true);
            return proof &&
                   validate_retirement(target_paths, *proof, journal_key.value);
        };

        if (!missing(*retired_status)) {
            auto has_retired_file =
                validate_artifact_directory(retired, "journal artifact");
            if (!has_retired_file) {
                return InspectionResult::Corrupted;
            }
            if (!*has_retired_file) {
                std::error_code error;
                return std::filesystem::is_empty(retired, error) && !error
                           ? InspectionResult::Retired
                           : InspectionResult::Corrupted;
            }
            const Paths root_paths{retired / "snapshot.enc",
                                   retired / "snapshot.enc.new",
                                   retired / "transaction.log.enc"};
            return validate_retired_tip(root_paths)
                       ? InspectionResult::Retired
                       : InspectionResult::Corrupted;
        }

        if (!validate_artifact_directory(active, "journal artifact")) {
            return InspectionResult::Corrupted;
        }

        auto retirement_file_status = read_status(retirement_path(paths));
        if (!retirement_file_status) {
            return InspectionResult::Corrupted;
        }
        if (!missing(*retirement_file_status)) {
            return validate_retired_tip(paths) ? InspectionResult::Retired
                                               : InspectionResult::Corrupted;
        }

        auto replayed = replay(paths, journal_key.value);
        return replayed ? InspectionResult::Active
                        : InspectionResult::Corrupted;
    } catch (...) {
        return InspectionResult::Corrupted;
    }
}

} // namespace kasumi::application::sync::journal
