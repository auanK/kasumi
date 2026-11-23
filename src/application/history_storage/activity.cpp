#include "application/history_storage/activity.hpp"

#include "application/history_storage/detail.hpp"
#include "core/wire.hpp"
#include "crypto/file_crypto.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <system_error>
#include <tuple>
#include <utility>

namespace kasumi::application::history_storage::activity {
namespace {

inline constexpr std::array<std::byte, 4> kact_magic{
    std::byte{'K'}, std::byte{'A'}, std::byte{'C'}, std::byte{'T'}};
inline constexpr std::uint8_t kact_version = 1U;
inline constexpr std::size_t timestamp_width = 20;
inline constexpr std::uint32_t known_flags_mask =
    flag_analysis_only | flag_barrier_already_absent |
    flag_barrier_release_failed | flag_mutation_uncertain;
inline constexpr std::size_t maximum_ciphertext_size =
    maximum_encoded_size + crypto::FILE_HEADER_SIZE +
    crypto::CHUNK_PREFIX_SIZE + crypto::MAC_SIZE + 256U;

bool valid_hex_32(std::string_view value) noexcept {
    if (value.size() != event_id_hex_size) {
        return false;
    }
    return std::ranges::all_of(value, [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

bool valid_operation(std::uint8_t raw) noexcept {
    return raw >= static_cast<std::uint8_t>(ActivityOperation::Fsck) &&
           raw <= static_cast<std::uint8_t>(ActivityOperation::RemoveBarrier);
}

bool valid_outcome(std::uint8_t raw) noexcept {
    return raw >= static_cast<std::uint8_t>(ActivityOutcome::Succeeded) &&
           raw <= static_cast<std::uint8_t>(ActivityOutcome::Uncertain);
}

std::size_t decode_utf8_codepoint(std::string_view input,
                                  std::uint32_t& cp) noexcept {
    if (input.empty()) {
        return 0;
    }
    const auto b0 = static_cast<unsigned char>(input[0]);
    if (b0 < 0x80U) {
        cp = b0;
        return 1;
    }
    if (b0 >= 0xC2U && b0 <= 0xDFU) {
        if (input.size() < 2) {
            return 0;
        }
        const auto b1 = static_cast<unsigned char>(input[1]);
        if ((b1 & 0xC0U) != 0x80U) {
            return 0;
        }
        cp = ((static_cast<std::uint32_t>(b0) & 0x1FU) << 6U) |
             (static_cast<std::uint32_t>(b1) & 0x3FU);
        return 2;
    }
    if (b0 >= 0xE0U && b0 <= 0xEFU) {
        if (input.size() < 3) {
            return 0;
        }
        const auto b1 = static_cast<unsigned char>(input[1]);
        const auto b2 = static_cast<unsigned char>(input[2]);
        if ((b1 & 0xC0U) != 0x80U || (b2 & 0xC0U) != 0x80U) {
            return 0;
        }
        if ((b0 == 0xE0U && b1 < 0xA0U) || (b0 == 0xEDU && b1 >= 0xA0U)) {
            return 0;
        }
        cp = ((static_cast<std::uint32_t>(b0) & 0x0FU) << 12U) |
             ((static_cast<std::uint32_t>(b1) & 0x3FU) << 6U) |
             (static_cast<std::uint32_t>(b2) & 0x3FU);
        return 3;
    }
    if (b0 >= 0xF0U && b0 <= 0xF4U) {
        if (input.size() < 4) {
            return 0;
        }
        const auto b1 = static_cast<unsigned char>(input[1]);
        const auto b2 = static_cast<unsigned char>(input[2]);
        const auto b3 = static_cast<unsigned char>(input[3]);
        if ((b1 & 0xC0U) != 0x80U || (b2 & 0xC0U) != 0x80U ||
            (b3 & 0xC0U) != 0x80U) {
            return 0;
        }
        if ((b0 == 0xF0U && b1 < 0x90U) || (b0 == 0xF4U && b1 > 0x8FU)) {
            return 0;
        }
        cp = ((static_cast<std::uint32_t>(b0) & 0x07U) << 18U) |
             ((static_cast<std::uint32_t>(b1) & 0x3FU) << 12U) |
             ((static_cast<std::uint32_t>(b2) & 0x3FU) << 6U) |
             (static_cast<std::uint32_t>(b3) & 0x3FU);
        return 4;
    }
    return 0;
}

bool valid_utf8_no_controls(std::string_view text,
                            std::size_t max_bytes,
                            bool allow_empty) noexcept {
    if ((!allow_empty && text.empty()) || text.size() > max_bytes) {
        return false;
    }
    std::size_t i = 0;
    while (i < text.size()) {
        std::uint32_t cp = 0;
        const std::size_t len = decode_utf8_codepoint(text.substr(i), cp);
        if (len == 0) {
            return false;
        }
        if (cp < 0x20U || cp == 0x7FU || (cp >= 0x80U && cp <= 0x9FU)) {
            return false;
        }
        i += len;
    }
    return true;
}

std::optional<std::array<std::uint8_t, event_id_byte_count>>
parse_hex_16(std::string_view hex) noexcept {
    if (!valid_hex_32(hex)) {
        return std::nullopt;
    }
    auto nibble = [](char ch) noexcept -> std::uint8_t {
        return static_cast<std::uint8_t>(ch >= 'a' ? (ch - 'a' + 10)
                                                   : (ch - '0'));
    };
    std::array<std::uint8_t, event_id_byte_count> bytes{};
    for (std::size_t i = 0; i < event_id_byte_count; ++i) {
        bytes[i] = static_cast<std::uint8_t>((nibble(hex[i * 2]) << 4U) |
                                             nibble(hex[i * 2 + 1]));
    }
    return bytes;
}

std::string
encode_hex_16(const std::array<std::uint8_t, event_id_byte_count>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(event_id_hex_size);
    for (const auto b : bytes) {
        out.push_back(digits[(b >> 4U) & 0x0FU]);
        out.push_back(digits[b & 0x0FU]);
    }
    return out;
}

std::expected<std::optional<ActivityRecord>, Error>
read_and_decode_activity_file(
    const std::filesystem::path& encrypted_path,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const Reference& expected_ref) {
    std::error_code fs_err;
    const auto file_size = std::filesystem::file_size(encrypted_path, fs_err);
    if (fs_err || file_size > maximum_ciphertext_size) {
        return std::nullopt;
    }
    auto encrypted = detail::read_file(encrypted_path, maximum_ciphertext_size);
    if (!encrypted) {
        if (encrypted.error().code == ErrorCode::LimitExceeded) {
            return std::nullopt;
        }
        return std::unexpected(encrypted.error());
    }
    auto plain =
        crypto::decrypt_bytes(*encrypted, key, crypto::FilePurpose::Activity);
    if (!plain) {
        return std::nullopt;
    }
    auto decoded = decode(*plain);
    if (!decoded) {
        return std::nullopt;
    }
    if (decoded->finished_at != expected_ref.finished_at ||
        decoded->event_id != expected_ref.event_id) {
        return std::nullopt;
    }
    return decoded;
}

} // namespace

std::string sanitize_text(std::string_view raw, std::size_t max_bytes) {
    while (!raw.empty() && (raw.front() == ' ' || raw.front() == '\t' ||
                            raw.front() == '\r' || raw.front() == '\n')) {
        raw.remove_prefix(1);
    }
    while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t' ||
                            raw.back() == '\r' || raw.back() == '\n')) {
        raw.remove_suffix(1);
    }

    std::string out;
    out.reserve(std::min(raw.size(), max_bytes));
    std::size_t offset = 0;
    while (offset < raw.size()) {
        std::uint32_t cp = 0;
        const std::size_t seq_len =
            decode_utf8_codepoint(raw.substr(offset), cp);
        if (seq_len == 0) {
            ++offset;
            continue;
        }
        const bool is_control =
            cp < 0x20U || cp == 0x7FU || (cp >= 0x80U && cp <= 0x9FU);
        if (is_control) {
            if (!out.empty() && out.back() != ' ' && out.size() < max_bytes) {
                out.push_back(' ');
            }
            offset += seq_len;
            continue;
        }
        if (out.size() + seq_len > max_bytes) {
            break;
        }
        out.append(raw.substr(offset, seq_len));
        offset += seq_len;
    }
    while (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return out;
}

bool valid_record(const ActivityRecord& record) noexcept {
    if (!valid_hex_32(record.event_id) ||
        !valid_operation(static_cast<std::uint8_t>(record.operation)) ||
        !valid_outcome(static_cast<std::uint8_t>(record.outcome))) {
        return false;
    }
    const bool non_zero_event =
        std::ranges::any_of(*parse_hex_16(record.event_id), [](std::uint8_t b) {
            return b != 0;
        });
    const bool non_zero_machine =
        std::ranges::any_of(record.machine_id, [](std::uint8_t b) {
            return b != 0;
        });
    if (!non_zero_event || !non_zero_machine) {
        return false;
    }
    if (record.started_at <= 0 || record.finished_at <= 0 ||
        record.finished_at < record.started_at) {
        return false;
    }
    if ((record.flags & ~known_flags_mask) != 0U) {
        return false;
    }
    return valid_utf8_no_controls(
               record.machine_name, maximum_machine_name_bytes, false) &&
           valid_utf8_no_controls(record.stage, maximum_stage_bytes, true) &&
           valid_utf8_no_controls(record.detail, maximum_detail_bytes, true);
}

std::expected<std::string, Error> object_identifier(const RemoteLayout& layout,
                                                    std::int64_t finished_at,
                                                    std::string_view event_id) {
    if (finished_at <= 0 || !valid_hex_32(event_id)) {
        return std::unexpected(detail::error(
            ErrorCode::InvalidInput, "invalid activity object reference"));
    }
    auto ts_text = std::to_string(finished_at);
    if (ts_text.size() < timestamp_width) {
        ts_text.insert(ts_text.begin(), timestamp_width - ts_text.size(), '0');
    }
    return layout.activity_prefix + ts_text + '-' + std::string{event_id};
}

std::optional<Reference> parse_object_identifier(const RemoteLayout& layout,
                                                 std::string_view identifier) {
    if (!identifier.starts_with(layout.activity_prefix)) {
        return std::nullopt;
    }
    const auto body = identifier.substr(layout.activity_prefix.size());
    if (body.size() != timestamp_width + 1 + event_id_hex_size ||
        body[timestamp_width] != '-') {
        return std::nullopt;
    }
    const auto ts_text = body.substr(0, timestamp_width);
    if (!std::ranges::all_of(ts_text, [](char c) {
            return c >= '0' && c <= '9';
        })) {
        return std::nullopt;
    }
    std::int64_t finished_at = 0;
    const auto parsed = std::from_chars(
        ts_text.data(), ts_text.data() + ts_text.size(), finished_at);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != ts_text.data() + ts_text.size() || finished_at <= 0) {
        return std::nullopt;
    }
    const auto event_id = body.substr(timestamp_width + 1);
    if (!valid_hex_32(event_id)) {
        return std::nullopt;
    }
    return Reference{.finished_at = finished_at,
                     .event_id = std::string{event_id}};
}

std::expected<std::vector<std::uint8_t>, Error>
encode(const ActivityRecord& record) {
    if (!valid_record(record)) {
        return std::unexpected(
            detail::error(ErrorCode::InvalidInput, "invalid activity record"));
    }
    return detail::guard_alloc(
        [&]() -> std::expected<std::vector<std::uint8_t>, Error> {
            wire::Writer writer;
            wire::write_array(writer, kact_magic);
            wire::write(writer, kact_version);
            const auto event_bytes = parse_hex_16(record.event_id).value();
            wire::write_bytes(writer, std::as_bytes(std::span{event_bytes}));
            wire::write(writer, static_cast<std::uint8_t>(record.operation));
            wire::write(writer, static_cast<std::uint8_t>(record.outcome));
            wire::write_bytes(writer,
                              std::as_bytes(std::span{record.machine_id}));
            wire::write_string(writer, record.machine_name);
            wire::write<std::int64_t>(writer, record.started_at);
            wire::write<std::int64_t>(writer, record.finished_at);
            wire::write<std::uint64_t>(writer, record.duration_ms);
            wire::write<std::uint64_t>(writer, record.metric_primary);
            wire::write<std::uint64_t>(writer, record.metric_secondary);
            wire::write<std::uint64_t>(writer, record.metric_bytes);
            wire::write<std::uint32_t>(writer, record.flags);
            wire::write_string(writer, record.stage);
            wire::write_string(writer, record.detail);
            if (writer.buffer.size() > maximum_encoded_size) {
                return std::unexpected(
                    detail::error(ErrorCode::LimitExceeded,
                                  "activity record exceeds maximum size"));
            }
            std::vector<std::uint8_t> out(writer.buffer.size());
            std::memcpy(out.data(), writer.buffer.data(), writer.buffer.size());
            return out;
        });
}

std::expected<ActivityRecord, Error>
decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > maximum_encoded_size) {
        return std::unexpected(detail::error(
            ErrorCode::LimitExceeded, "activity record exceeds maximum size"));
    }
    return detail::guard_alloc([&]() -> std::expected<ActivityRecord, Error> {
        wire::Reader reader{std::as_bytes(bytes)};
        auto magic = wire::read_array<kact_magic.size()>(reader);
        if (!magic || *magic != kact_magic) {
            return std::unexpected(
                detail::error(ErrorCode::InvalidCommit, "invalid KACT magic"));
        }
        auto version = wire::read<std::uint8_t>(reader);
        if (!version || *version != kact_version) {
            return std::unexpected(detail::error(ErrorCode::InvalidCommit,
                                                 "unsupported KACT version"));
        }
        auto event_bytes = wire::read_array<event_id_byte_count>(reader);
        auto raw_op = wire::read<std::uint8_t>(reader);
        auto raw_outcome = wire::read<std::uint8_t>(reader);
        auto machine_bytes = wire::read_array<machine_id_byte_count>(reader);
        auto machine_name =
            wire::read_string(reader, maximum_machine_name_bytes);
        auto started_at = wire::read<std::int64_t>(reader);
        auto finished_at = wire::read<std::int64_t>(reader);
        auto duration_ms = wire::read<std::uint64_t>(reader);
        auto metric_primary = wire::read<std::uint64_t>(reader);
        auto metric_secondary = wire::read<std::uint64_t>(reader);
        auto metric_bytes = wire::read<std::uint64_t>(reader);
        auto flags = wire::read<std::uint32_t>(reader);
        auto stage = wire::read_string(reader, maximum_stage_bytes);
        auto detail_text = wire::read_string(reader, maximum_detail_bytes);
        if (!event_bytes || !raw_op || !raw_outcome || !machine_bytes ||
            !machine_name || !started_at || !finished_at || !duration_ms ||
            !metric_primary || !metric_secondary || !metric_bytes || !flags ||
            !stage || !detail_text || !reader.data.empty()) {
            return std::unexpected(detail::error(ErrorCode::InvalidCommit,
                                                 "malformed KACT payload"));
        }
        if (!valid_operation(*raw_op) || !valid_outcome(*raw_outcome)) {
            return std::unexpected(detail::error(
                ErrorCode::InvalidCommit, "invalid KACT operation or outcome"));
        }
        ActivityRecord record;
        std::array<std::uint8_t, event_id_byte_count> ev_raw{};
        std::memcpy(ev_raw.data(), event_bytes->data(), event_id_byte_count);
        record.event_id = encode_hex_16(ev_raw);
        record.operation = static_cast<ActivityOperation>(*raw_op);
        record.outcome = static_cast<ActivityOutcome>(*raw_outcome);
        std::memcpy(record.machine_id.data(),
                    machine_bytes->data(),
                    machine_id_byte_count);
        record.machine_name = std::move(*machine_name);
        record.started_at = *started_at;
        record.finished_at = *finished_at;
        record.duration_ms = *duration_ms;
        record.metric_primary = *metric_primary;
        record.metric_secondary = *metric_secondary;
        record.metric_bytes = *metric_bytes;
        record.flags = *flags;
        record.stage = std::move(*stage);
        record.detail = std::move(*detail_text);
        if (!valid_record(record)) {
            return std::unexpected(
                detail::error(ErrorCode::InvalidCommit, "invalid KACT fields"));
        }
        return record;
    });
}

std::expected<std::string, Error>
publish(transport::Transport& storage,
        const RemoteLayout& layout,
        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
        const ActivityRecord& record,
        const std::filesystem::path& workspace_root) {
    if (!transport::valid(storage)) {
        return std::unexpected(
            detail::error(ErrorCode::InvalidInput, "invalid transport"));
    }
    auto identifier =
        object_identifier(layout, record.finished_at, record.event_id);
    if (!identifier) {
        return std::unexpected(identifier.error());
    }
    auto encoded = encode(record);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    auto encrypted =
        crypto::encrypt_bytes(*encoded, key, crypto::FilePurpose::Activity);
    if (!encrypted) {
        return std::unexpected(detail::error(
            ErrorCode::CryptoFailure, "failed to encrypt activity record"));
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(temporary.error());
    }
    const auto temp_path = (*temporary)->workspace.root / "activity.enc";
    if (auto written = detail::write_file(temp_path, *encrypted); !written) {
        return std::unexpected(written.error());
    }
    auto uploaded = transport::put(storage, temp_path, *identifier);
    detail::remove_file(temp_path);
    if (!uploaded) {
        return std::unexpected(detail::transport_error(uploaded.error()));
    }
    return *identifier;
}

std::expected<ActivityInventory, Error>
load_all(transport::Transport& storage,
         const RemoteLayout& layout,
         std::span<const std::uint8_t, crypto::KEY_SIZE> key,
         const std::filesystem::path& workspace_root,
         std::optional<std::span<const std::string>> known_identifiers) {
    if (!transport::valid(storage)) {
        return std::unexpected(
            detail::error(ErrorCode::InvalidInput, "invalid transport"));
    }
    std::vector<std::string> identifiers;
    if (known_identifiers) {
        for (const auto& identifier : *known_identifiers) {
            if (is_activity_object(layout, identifier)) {
                identifiers.push_back(identifier);
            }
        }
    } else {
        auto listed = detail::list_identifiers(storage, layout.activity_prefix);
        if (!listed) {
            return std::unexpected(listed.error());
        }
        identifiers.reserve(listed->size());
        for (const auto& name : *listed) {
            identifiers.push_back(name.starts_with(layout.activity_prefix)
                                      ? name
                                      : layout.activity_prefix + name);
        }
    }
    detail::sort_unique(identifiers);
    if (identifiers.size() > maximum_activity_object_count) {
        return std::unexpected(detail::error(
            ErrorCode::LimitExceeded, "too many remote activity objects"));
    }

    ActivityInventory result;
    if (identifiers.empty()) {
        return result;
    }

    struct Pending {
        std::string identifier;
        std::string filename;
        Reference ref;
    };
    std::vector<Pending> candidates;
    candidates.reserve(identifiers.size());
    for (const auto& id : identifiers) {
        auto parsed = parse_object_identifier(layout, id);
        if (!parsed) {
            result.invalid_objects.push_back(id);
            continue;
        }
        candidates.push_back(Pending{
            .identifier = id,
            .filename = id.substr(layout.activity_prefix.size()),
            .ref = std::move(*parsed),
        });
    }
    if (candidates.empty()) {
        return result;
    }

    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(temporary.error());
    }

    if (storage.storage.get_batch != nullptr && candidates.size() >= 2) {
        transport::GetBatch batch{
            .source_prefix = std::string{detail::trim_trailing_slash(
                layout.activity_prefix)},
            .destination_root = (*temporary)->workspace.root,
            .identifiers = {},
        };
        batch.identifiers.reserve(candidates.size());
        for (const auto& cand : candidates) {
            batch.identifiers.push_back(cand.filename);
        }
        auto prefetched = transport::get_batch(storage, batch);
        if (!prefetched &&
            prefetched.error().code != transport::ErrorCode::Unsupported) {
            return std::unexpected(detail::transport_error(prefetched.error()));
        }
    }

    std::size_t sequence = 0;
    for (const auto& cand : candidates) {
        auto path = (*temporary)->workspace.root / cand.filename;
        std::error_code fs_err;
        if (!std::filesystem::is_regular_file(path, fs_err)) {
            path = (*temporary)->workspace.root /
                   ("act-" + std::to_string(sequence++));
            auto downloaded = transport::get(storage, cand.identifier, path);
            if (!downloaded) {
                detail::remove_file(path);
                if (downloaded.error().code ==
                    transport::ErrorCode::ObjectNotFound) {
                    // Tolerate concurrent pruning during unlocked inspection.
                    continue;
                }
                return std::unexpected(
                    detail::transport_error(downloaded.error()));
            }
        }
        auto decoded = read_and_decode_activity_file(path, key, cand.ref);
        detail::remove_file(path);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        if (!decoded->has_value()) {
            result.invalid_objects.push_back(cand.identifier);
            continue;
        }
        result.valid.push_back(LoadedActivity{
            .identifier = cand.identifier,
            .record = std::move(**decoded),
        });
    }

    std::ranges::sort(
        result.valid,
        [](const LoadedActivity& left, const LoadedActivity& right) {
            if (left.record.finished_at != right.record.finished_at) {
                return left.record.finished_at > right.record.finished_at;
            }
            return left.record.event_id < right.record.event_id;
        });
    return result;
}

std::vector<std::string> plan_pruning(std::span<const LoadedActivity> valid,
                                      const epoch::RetentionPolicy& policy,
                                      std::int64_t reference_now) {
    using GroupKey = std::pair<std::array<std::uint8_t, machine_id_byte_count>,
                               ActivityOperation>;
    std::map<GroupKey, std::vector<const LoadedActivity*>> groups;
    for (const auto& item : valid) {
        groups[GroupKey{item.record.machine_id, item.record.operation}]
            .push_back(&item);
    }

    const std::size_t min_depth =
        std::max<std::size_t>(1U, policy.min_history_depth);
    const std::uint64_t age_limit_seconds =
        static_cast<std::uint64_t>(policy.min_history_age_hours) * 3600ULL;

    std::vector<std::string> prunable;
    for (auto& [unused, items] : groups) {
        static_cast<void>(unused);
        std::ranges::sort(
            items, [](const LoadedActivity* left, const LoadedActivity* right) {
                if (left->record.finished_at != right->record.finished_at) {
                    return left->record.finished_at > right->record.finished_at;
                }
                return left->record.event_id < right->record.event_id;
            });

        bool kept_latest_success = false;
        for (std::size_t index = 0; index < items.size(); ++index) {
            const auto& item = *items[index];
            const bool keep_depth = index < min_depth;
            bool keep_age = false;
            if (reference_now <= 0 || item.record.finished_at > reference_now) {
                keep_age = true;
            } else {
                const auto age = static_cast<std::uint64_t>(
                    reference_now - item.record.finished_at);
                keep_age = age < age_limit_seconds;
            }
            bool keep_success = false;
            if (!kept_latest_success &&
                item.record.outcome == ActivityOutcome::Succeeded) {
                kept_latest_success = true;
                keep_success = true;
            }
            if (!keep_depth && !keep_age && !keep_success) {
                prunable.push_back(item.identifier);
            }
        }
    }
    detail::sort_unique(prunable);
    return prunable;
}

} // namespace kasumi::application::history_storage::activity
