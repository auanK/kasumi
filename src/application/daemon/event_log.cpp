#include "application/daemon/event_log.hpp"

#include "application/daemon/session_state.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <nlohmann/json.hpp>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::application::daemon_detail {
namespace {

constexpr std::size_t kMaxEventRingSize = 512U;
constexpr std::uint64_t kMaxDaemonLogBytes = 2ULL * 1024ULL * 1024ULL;

std::filesystem::path
daemon_log_path(const std::filesystem::path& app_data_dir) {
    return app_data_dir / "daemon.log";
}

std::filesystem::path
daemon_rotated_log_path(const std::filesystem::path& app_data_dir) {
    return app_data_dir / "daemon.log.1";
}

bool safe_regular_or_absent(const std::filesystem::path& path,
                            std::uint64_t* out_size = nullptr) noexcept {
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(path, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        (!ec && st.type() == std::filesystem::file_type::not_found)) {
        if (out_size != nullptr) {
            *out_size = 0;
        }
        return true;
    }
    if (ec || std::filesystem::is_symlink(st) ||
        !std::filesystem::is_regular_file(st)) {
        return false;
    }
    if (out_size != nullptr) {
        const auto sz = std::filesystem::file_size(path, ec);
        *out_size = ec ? 0ULL : static_cast<std::uint64_t>(sz);
    }
    return true;
}

void read_log_file_into(const std::filesystem::path& path,
                        std::vector<DaemonEvent>& out,
                        std::uint64_t& max_seq) {
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(path, ec);
    if (ec || std::filesystem::is_symlink(st) ||
        !std::filesystem::is_regular_file(st)) {
        return;
    }
    std::string content;
    std::array<std::uint8_t, 8192> buf{};
    const auto streamed = platform::private_storage::stream_regular_file(
        path, buf, [&](std::span<const std::uint8_t> chunk) {
            if (content.size() + chunk.size() > 4ULL * 1024ULL * 1024ULL) {
                return false;
            }
            content.append(reinterpret_cast<const char*>(chunk.data()),
                           chunk.size());
            return true;
        });
    if (!streamed) {
        return;
    }
    std::size_t pos = 0;
    while (pos < content.size()) {
        const std::size_t nl = content.find('\n', pos);
        const std::size_t end = nl == std::string::npos ? content.size() : nl;
        std::string_view line{content.data() + pos, end - pos};
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        pos = (nl == std::string::npos) ? content.size() : nl + 1U;
        if (line.empty()) {
            continue;
        }
        try {
            const auto j = nlohmann::json::parse(line);
            if (!j.is_object()) {
                continue;
            }
            DaemonEvent ev{
                .seq = j.value("seq", std::uint64_t{0}),
                .timestamp_unix = j.value("ts", std::int64_t{0}),
                .profile_name = j.value("profile", std::string{}),
                .kind = j.value("kind", std::string{}),
                .detail = j.value("detail", std::string{}),
            };
            if (ev.seq > max_seq) {
                max_seq = ev.seq;
            }
            out.push_back(std::move(ev));
        } catch (...) {
        }
    }
}

} // namespace

void append_daemon_log_line_best_effort(
    const std::filesystem::path& app_data_dir, const DaemonEvent& ev) noexcept {
    if (app_data_dir.empty()) {
        return;
    }
    try {
        if (!platform::private_storage::ensure_directory(app_data_dir)) {
            return;
        }
        const auto primary = daemon_log_path(app_data_dir);
        const auto rotated = daemon_rotated_log_path(app_data_dir);
        std::uint64_t cur_size = 0;
        if (!safe_regular_or_absent(primary, &cur_size) ||
            !safe_regular_or_absent(rotated)) {
            return;
        }
        if (cur_size >= kMaxDaemonLogBytes) {
            std::error_code ec;
            std::filesystem::remove(rotated, ec);
            ec.clear();
            std::filesystem::rename(primary, rotated, ec);
            if (!ec) {
                static_cast<void>(
                    platform::private_storage::protect_file(rotated));
            }
        }
        const bool existed = std::filesystem::exists(primary);
        if (!existed) {
            if (!platform::private_storage::create_file(primary)) {
                return;
            }
        }
        nlohmann::json row{
            {"seq", ev.seq},
            {"ts", ev.timestamp_unix},
            {"profile", ev.profile_name},
            {"kind", ev.kind},
            {"detail", ev.detail},
        };
        std::ofstream out(primary, std::ios::binary | std::ios::app);
        if (out) {
            out << row.dump() << '\n';
            out.flush();
        }
        if (!existed) {
            static_cast<void>(platform::private_storage::protect_file(primary));
        }
    } catch (...) {
    }
}

void emit_daemon_event(DaemonSessionState& state,
                       std::string profile_name,
                       std::string kind,
                       std::string detail,
                       bool persist_to_log) noexcept {
    DaemonEvent ev{
        .timestamp_unix = current_unix_seconds(),
        .profile_name = std::move(profile_name),
        .kind = std::move(kind),
        .detail = std::move(detail),
    };
    DaemonEventCallback cb;
    try {
        {
            std::lock_guard lock(state.event_log_mutex);
            ev.seq = state.next_event_seq++;
            state.event_ring.push_back(ev);
            while (state.event_ring.size() > kMaxEventRingSize) {
                state.event_ring.pop_front();
            }
            state.latest_event_seq.store(ev.seq, std::memory_order_release);
            if (persist_to_log) {
                daemon_detail::append_daemon_log_line_best_effort(
                    state.environment.app_data_dir, ev);
            }
        }
        daemon_detail::notify_daemon_status_change(state);
        cb = state.options.on_event;
    } catch (...) {
        return;
    }
    if (cb) {
        try {
            cb(ev);
        } catch (...) {
        }
    }
}

DaemonLogsReport
merge_daemon_log_events(const std::filesystem::path& app_data_dir,
                        const std::deque<DaemonEvent>* live_ring,
                        const DaemonLogQuery& query) {
    std::vector<DaemonEvent> raw;
    std::uint64_t disk_max_seq = 0;
    if (!app_data_dir.empty()) {
        read_log_file_into(
            daemon_rotated_log_path(app_data_dir), raw, disk_max_seq);
        read_log_file_into(daemon_log_path(app_data_dir), raw, disk_max_seq);
    }
    std::uint64_t latest_seq = disk_max_seq;
    if (live_ring != nullptr && !live_ring->empty()) {
        latest_seq = std::max(latest_seq, live_ring->back().seq);
        // Only the current session's retained events can overlap the ring.
        // Keep the original order of earlier on-disk events.
        const auto first_live_seq = live_ring->front().seq;
        const auto tail = std::ranges::find_if(raw, [&](const DaemonEvent& ev) {
            return ev.seq >= first_live_seq;
        });
        const auto start = tail - raw.begin();
        std::unordered_set<std::uint64_t> persisted;
        for (auto it = tail; it != raw.end(); ++it) {
            persisted.insert(it->seq);
        }
        for (const auto& ev : *live_ring) {
            if (!persisted.contains(ev.seq)) {
                raw.push_back(ev);
            }
        }
        std::ranges::stable_sort(
            raw.begin() + start, raw.end(), {}, &DaemonEvent::seq);
    }

    std::vector<DaemonEvent> filtered;
    filtered.reserve(raw.size());
    for (auto& ev : raw) {
        if (ev.seq <= query.since_seq) {
            continue;
        }
        if (query.profile_name && !query.profile_name->empty() &&
            ev.profile_name != *query.profile_name) {
            continue;
        }
        filtered.push_back(std::move(ev));
    }

    const std::size_t max_lines =
        query.max_lines == 0 ? 100U
                             : std::min<std::size_t>(query.max_lines, 1000U);
    if (filtered.size() > max_lines) {
        filtered.erase(filtered.begin(),
                       filtered.end() - static_cast<std::ptrdiff_t>(max_lines));
    }

    return DaemonLogsReport{
        .log_path = app_data_dir.empty() ? std::string{}
                                         : platform::path::to_utf8(
                                               daemon_log_path(app_data_dir)),
        .latest_seq = latest_seq,
        .events = std::move(filtered),
    };
}

} // namespace kasumi::application::daemon_detail
