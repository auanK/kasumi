#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_REMOTE_LAYOUT_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_REMOTE_LAYOUT_HPP

#include "application/history_storage/epoch.hpp"
#include "application/history_storage/history_storage.hpp"
#include "crypto/key_derivation.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace kasumi::application::history_storage {

struct RemoteLayout {
    std::string history_prefix;
    std::string commits_prefix;
    std::string heads_prefix;
    std::string epochs_prefix;
    std::string gc_prefix;
    std::string barrier_identifier;
    std::string writers_prefix;
    std::string probes_prefix;
    std::string quarantine_prefix;
    std::string quarantine_content_prefix;
    std::string quarantine_commits_prefix;
};

RemoteLayout default_remote_layout();

RemoteLayout derive_remote_layout(
    std::span<const std::uint8_t, crypto::KEY_SIZE> master_key);

std::string marker_object(const RemoteLayout& layout,
                          const HeadReference& reference);
std::optional<HeadReference> parse_marker_object(const RemoteLayout& layout,
                                                 std::string_view identifier);

std::string commit_object(const RemoteLayout& layout,
                          const HeadReference& reference);
std::optional<HeadReference> parse_commit_object(const RemoteLayout& layout,
                                                 std::string_view identifier);

std::string epoch_object(const RemoteLayout& layout,
                         std::uint64_t sequence,
                         std::string_view epoch_id);
std::string epoch_object(const RemoteLayout& layout,
                         const epoch::Reference& reference);
std::optional<epoch::Reference> parse_epoch_object(const RemoteLayout& layout,
                                                   std::string_view identifier);

bool is_control_object(const RemoteLayout& layout,
                       std::string_view identifier) noexcept;
bool is_history_object(const RemoteLayout& layout,
                       std::string_view identifier) noexcept;

std::optional<std::string>
quarantine_identifier(const RemoteLayout& layout,
                      std::string_view original_identifier);
std::optional<std::string>
restore_destination(const RemoteLayout& layout,
                    std::string_view quarantine_identifier);

} // namespace kasumi::application::history_storage

#endif
