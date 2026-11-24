#ifndef KASUMI_CLI_HELP_TOPICS_HPP
#define KASUMI_CLI_HELP_TOPICS_HPP

#include "cli/i18n.hpp"

#include <array>
#include <string_view>

namespace kasumi::cli {

struct HelpTopic {
    std::string_view name;
    i18n::Key key;
};

inline constexpr auto help_topics = std::to_array<HelpTopic>({
    {"sync", i18n::Key::HelpSync},
    {"status", i18n::Key::HelpStatus},
    {"fsck", i18n::Key::HelpFsck},
    {"gc", i18n::Key::HelpGc},
    {"gc remove-writer", i18n::Key::HelpGcRemoveWriter},
    {"gc remove-barrier", i18n::Key::HelpGcRemoveBarrier},
    {"repack", i18n::Key::HelpRepack},
    {"resolve-missing", i18n::Key::HelpResolveMissing},
    {"remote", i18n::Key::HelpRemote},
    {"config", i18n::Key::HelpConfig},
    {"list", i18n::Key::HelpList},
    {"show", i18n::Key::HelpShow},
    {"diagnostics", i18n::Key::HelpDiagnostics},
    {"key", i18n::Key::HelpKey},
    {"profile", i18n::Key::HelpProfile},
    {"profile create", i18n::Key::HelpProfileCreate},
    {"profile edit", i18n::Key::HelpProfileEdit},
    {"profile clone", i18n::Key::HelpProfileClone},
    {"profile storage", i18n::Key::HelpProfileStorage},
    {"profile rename", i18n::Key::HelpProfileRename},
    {"profile delete", i18n::Key::HelpProfileDelete},
    {"profile test", i18n::Key::HelpProfileTest},
    {"ignore", i18n::Key::HelpIgnore},
    {"ignore check", i18n::Key::HelpIgnoreCheck},
    {"ignore init", i18n::Key::HelpIgnoreInit},
    {"conflicts", i18n::Key::HelpConflicts},
    {"conflicts resolve", i18n::Key::HelpConflictsResolve},
    {"completion", i18n::Key::HelpCompletion},
    {"remote heads", i18n::Key::HelpRemoteHeads},
    {"remote tree", i18n::Key::HelpRemoteTree},
    {"remote commits", i18n::Key::HelpRemoteCommits},
    {"remote summary", i18n::Key::HelpRemoteSummary},
    {"remote stat", i18n::Key::HelpRemoteStat},
    {"remote log", i18n::Key::HelpRemoteLog},
    {"remote commit", i18n::Key::HelpRemoteCommit},
    {"remote get", i18n::Key::HelpRemoteGet},
    {"remote restore", i18n::Key::HelpRemoteRestore},
    {"remote epochs", i18n::Key::HelpRemoteEpochs},
    {"remote epoch", i18n::Key::HelpRemoteEpoch},
    {"remote contents", i18n::Key::HelpRemoteContents},
    {"remote content", i18n::Key::HelpRemoteContent},
    {"remote markers", i18n::Key::HelpRemoteMarkers},
    {"remote objects", i18n::Key::HelpRemoteObjects},
    {"remote orphans", i18n::Key::HelpRemoteOrphans},
    {"remote writers", i18n::Key::HelpRemoteWriters},
    {"remote health", i18n::Key::HelpRemoteHealth},
});

} // namespace kasumi::cli

#endif
