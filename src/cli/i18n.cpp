#include "cli/i18n.hpp"
#include "cli/i18n_embedded.hpp"
#include "application/environment.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace kasumi::cli::i18n {

namespace {

constexpr std::size_t KEY_COUNT =
    static_cast<std::size_t>(Key::WizardConfigReadFailed) + 1;

struct KeyMapping {
    Key key;
    const char* path;
};

constexpr KeyMapping KEY_MAPPINGS[] = {
    {Key::LabelError, "labels.error"},
    {Key::LabelWarning, "labels.warning"},
    {Key::LabelOk, "labels.ok"},
    {Key::LabelYes, "labels.yes"},
    {Key::LabelNo, "labels.no"},

    {Key::HelpText, "help_text"},
    {Key::VersionText, "version_text"},

    {Key::SyncInProgress, "sync.in_progress"},
    {Key::SyncCompleted, "sync.completed"},
    {Key::SyncNothingToDo, "sync.nothing_to_do"},
    {Key::SyncPlanHeader, "sync.plan_header"},
    {Key::SyncConflictsWarning, "sync.conflicts_warning"},
    {Key::SyncConflictsStatusHint, "sync.conflicts_status_hint"},
    {Key::SyncSummaryHeader, "sync.summary_header"},
    {Key::SyncEstimatedTraffic, "sync.estimated_traffic"},
    {Key::SyncUpload, "sync.upload"},
    {Key::SyncDownload, "sync.download"},
    {Key::PreviewCompleted, "sync.preview_completed"},

    {Key::ErrorPlanCalculation, "errors.plan_calculation"},
    {Key::ErrorFsckFailed, "errors.fsck_failed"},
    {Key::ErrorFsckClean, "errors.fsck_clean"},
    {Key::ErrorFsckAuditing, "errors.fsck_auditing"},
    {Key::ErrorGcRunning, "errors.gc_running"},
    {Key::ErrorGcWarning, "errors.gc_warning"},
    {Key::ErrorGcCancelled, "errors.gc_cancelled"},
    {Key::ErrorGcCompleted, "errors.gc_completed"},
    {Key::ErrorSyncFailed, "errors.sync_failed"},
    {Key::ErrorInconsistentInspection, "errors.inconsistent_inspection"},
    {Key::ErrorAvailableHeads, "errors.available_heads"},
    {Key::ErrorUseRemoteTreeHead, "errors.use_remote_tree_head"},

    {Key::RemoteHeadsNone, "remote.heads_none"},
    {Key::RemoteHeadsHeader, "remote.heads_header"},
    {Key::RemoteTreeNone, "remote.tree_none"},
    {Key::RemoteTreeHead, "remote.tree_head"},
    {Key::RemoteTreeHeight, "remote.tree_height"},
    {Key::RemoteTreeFiles, "remote.tree_files"},
    {Key::RemoteTreeDirectories, "remote.tree_directories"},
    {Key::RemoteTreeSize, "remote.tree_size"},
    {Key::RemoteCommitsNone, "remote.commits_none"},
    {Key::RemoteCommitsHeader, "remote.commits_header"},
    {Key::RemoteSummaryHeader, "remote.summary_header"},
    {Key::RemoteSummaryHistoryPresent, "remote.summary_history_present"},
    {Key::RemoteSummaryHistoryAbsent, "remote.summary_history_absent"},
    {Key::RemoteStatHeader, "remote.stat_header"},
    {Key::RemoteStatView, "remote.stat_view"},
    {Key::RemoteStatDirectory, "remote.stat_directory"},
    {Key::RemoteStatFile, "remote.stat_file"},
    {Key::RemoteCommitHeader, "remote.commit_header"},
    {Key::RemoteFileSavedHeader, "remote.file_saved_header"},
    {Key::RemoteEpochsHeader, "remote.epochs_header"},
    {Key::RemoteEpochNone, "remote.epoch_none"},
    {Key::RemoteEpochDetailHeader, "remote.epoch_detail_header"},
    {Key::RemoteContentsHeader, "remote.contents_header"},
    {Key::RemoteAuditHeader, "remote.audit_header"},
    {Key::RemoteContentHeader, "remote.content_header"},
    {Key::RemoteMarkersHeader, "remote.markers_header"},
    {Key::RemoteObjectsHeader, "remote.objects_header"},
    {Key::RemoteOrphansHeader, "remote.orphans_header"},
    {Key::RemoteQuarantineHeader, "remote.quarantine_header"},
    {Key::RemoteWritersHeader, "remote.writers_header"},
    {Key::RemoteHealthHeader, "remote.health_header"},

    {Key::FieldCommit, "fields.commit"},
    {Key::FieldHeight, "fields.height"},
    {Key::FieldCreatedAt, "fields.created_at"},
    {Key::FieldParents, "fields.parents"},
    {Key::FieldFiles, "fields.files"},
    {Key::FieldDirectories, "fields.directories"},
    {Key::FieldSize, "fields.size"},
    {Key::FieldRoot, "fields.root"},
    {Key::FieldEntries, "fields.entries"},
    {Key::FieldLogicalHead, "fields.logical_head"},
    {Key::FieldPhysicalMarker, "fields.physical_marker"},
    {Key::FieldAncestralMarker, "fields.ancestral_marker"},
    {Key::FieldPhysicalVariants, "fields.physical_variants"},
    {Key::FieldCiphertext, "fields.ciphertext"},
    {Key::FieldObject, "fields.object"},
    {Key::FieldState, "fields.state"},
    {Key::FieldPath, "fields.path"},
    {Key::FieldDestination, "fields.destination"},
    {Key::FieldLogicalHash, "fields.logical_hash"},
    {Key::FieldSequence, "fields.sequence"},
    {Key::FieldEpochId, "fields.epoch_id"},
    {Key::FieldVaultId, "fields.vault_id"},
    {Key::FieldIssuedAt, "fields.issued_at"},
    {Key::FieldMinRetention, "fields.min_retention"},
    {Key::FieldPreviousEpoch, "fields.previous_epoch"},
    {Key::FieldNextEpoch, "fields.next_epoch"},
    {Key::FieldAnchors, "fields.anchors"},
    {Key::FieldType, "fields.type"},
    {Key::FieldModifiedAt, "fields.modified_at"},

    {Key::VariantValid, "variants.valid"},
    {Key::VariantInvalidCiphertext, "variants.invalid_ciphertext"},
    {Key::VariantInvalidCommit, "variants.invalid_commit"},
    {Key::VariantInvalid, "variants.invalid"},

    {Key::PromptPassword, "prompts.password"},
    {Key::PromptConfirmPassword, "prompts.confirm_password"},
    {Key::PromptSalt, "prompts.salt"},
    {Key::PromptConfirmSalt, "prompts.confirm_salt"},
    {Key::PasswordsDoNotMatch, "prompts.passwords_do_not_match"},
    {Key::SaltsDoNotMatch, "prompts.salts_do_not_match"},

    {Key::WizardHeader, "wizard.header"},
    {Key::WizardNoProfiles, "wizard.no_profiles"},
    {Key::WizardMenu, "wizard.menu"},
    {Key::WizardPromptProfileName, "wizard.prompt_profile_name"},
    {Key::WizardProfileAlreadyExists, "wizard.profile_already_exists"},
    {Key::WizardPromptLocalPath, "wizard.prompt_local_path"},
    {Key::WizardPromptRemotePath, "wizard.prompt_remote_path"},
    {Key::WizardLocalPathMustBeAbsolute, "wizard.local_path_must_be_absolute"},
    {Key::WizardRemotePathMustBeAbsolute, "wizard.remote_path_must_be_absolute"},
    {Key::WizardProfileCreated, "wizard.profile_created"},
    {Key::WizardProfileNotFound, "wizard.profile_not_found"},
    {Key::WizardPromptProfileToDelete, "wizard.prompt_profile_to_delete"},
    {Key::WizardProfileDeleted, "wizard.profile_deleted"},
    {Key::WizardPromptProfileToEdit, "wizard.prompt_profile_to_edit"},
    {Key::WizardPromptNewLocalPath, "wizard.prompt_new_local_path"},
    {Key::WizardPromptNewRemotePath, "wizard.prompt_new_remote_path"},
    {Key::WizardProfileEdited, "wizard.profile_edited"},
    {Key::WizardPromptProfileToRename, "wizard.prompt_profile_to_rename"},
    {Key::WizardPromptNewProfileName, "wizard.prompt_new_profile_name"},
    {Key::WizardProfileRenamed, "wizard.profile_renamed"},
    {Key::WizardInvalidOption, "wizard.invalid_option"},
    {Key::WizardConfigReadFailed, "wizard.config_read_failed"},
};

Language g_current_language = Language::English;
std::string g_current_language_code = "en";
std::array<std::string, KEY_COUNT> g_current_strings;
bool g_initialized = false;

void flatten_json(const nlohmann::json& j,
                  const std::string& prefix,
                  std::unordered_map<std::string, std::string>& out) {
    if (j.is_object()) {
        for (auto it = j.begin(); it != j.end(); ++it) {
            std::string key =
                prefix.empty() ? it.key() : prefix + "." + it.key();
            flatten_json(it.value(), key, out);
        }
    } else if (j.is_string()) {
        out[prefix] = j.get<std::string>();
    }
}

std::unordered_map<std::string, std::string> parse_catalog(
    std::string_view json_str) {
    std::unordered_map<std::string, std::string> map;
    try {
        const auto parsed = nlohmann::json::parse(json_str);
        flatten_json(parsed, "", map);
    } catch (...) {
        // Return whatever could be parsed
    }
    return map;
}

const std::unordered_map<std::string, std::string>& get_default_en_map() {
    static const auto s_map = parse_catalog(embedded::EN_JSON);
    return s_map;
}

void populate_strings_from_map(
    const std::unordered_map<std::string, std::string>& target_map) {
    const auto& default_en = get_default_en_map();
    for (const auto& mapping : KEY_MAPPINGS) {
        const auto idx = static_cast<std::size_t>(mapping.key);
        if (idx >= KEY_COUNT) {
            continue;
        }
        auto it = target_map.find(mapping.path);
        if (it != target_map.end() && !it->second.empty()) {
            g_current_strings[idx] = it->second;
        } else {
            auto def_it = default_en.find(mapping.path);
            if (def_it != default_en.end()) {
                g_current_strings[idx] = def_it->second;
            } else {
                g_current_strings[idx].clear();
            }
        }
    }
    g_initialized = true;
}

std::string try_read_file(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) ||
        !std::filesystem::is_regular_file(path, ec)) {
        return "";
    }
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
}

std::string find_external_locale_file(std::string_view code) {
    std::string filename = std::string(code) + ".json";

    std::vector<std::filesystem::path> search_paths;

    // 1. AppData / Config path
    const auto environment = application::default_execution_environment();
    search_paths.push_back(environment.app_data_dir / "locales" / filename);

    // 2. Working directory locales/
    search_paths.push_back(std::filesystem::current_path() / "locales" /
                           filename);

    for (const auto& path : search_paths) {
        auto content = try_read_file(path);
        if (!content.empty()) {
            return content;
        }
    }
    return "";
}

} // namespace

Language current_language() noexcept {
    return g_current_language;
}

std::string_view current_language_code() noexcept {
    return g_current_language_code;
}

void set_language(Language language) {
    g_current_language = language;
    switch (language) {
        case Language::Portuguese:
            g_current_language_code = "pt-BR";
            populate_strings_from_map(parse_catalog(embedded::PT_BR_JSON));
            break;
        case Language::English:
        case Language::Custom:
        default:
            g_current_language_code = "en";
            populate_strings_from_map(get_default_en_map());
            break;
    }
}

void set_language(std::string_view code) {
    std::string lower_code;
    lower_code.reserve(code.size());
    for (char c : code) {
        lower_code.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }

    g_current_language_code = std::string(code);

    // 1. Check for external locale file first
    auto external_content = find_external_locale_file(code);
    if (external_content.empty() && lower_code != code) {
        external_content = find_external_locale_file(lower_code);
    }

    if (!external_content.empty()) {
        auto custom_map = parse_catalog(external_content);
        if (!custom_map.empty()) {
            g_current_language = parse_language(code);
            populate_strings_from_map(custom_map);
            return;
        }
    }

    // 2. Fall back to embedded catalogs
    if (lower_code == "pt" || lower_code == "pt-br" || lower_code == "pt_br" ||
        lower_code == "portuguese") {
        g_current_language = Language::Portuguese;
        populate_strings_from_map(parse_catalog(embedded::PT_BR_JSON));
    } else {
        g_current_language = Language::English;
        populate_strings_from_map(get_default_en_map());
    }
}

Language parse_language(std::string_view code) noexcept {
    std::string lower;
    lower.reserve(code.size());
    for (char c : code) {
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    if (lower == "pt" || lower == "pt-br" || lower == "pt_br" ||
        lower == "portuguese") {
        return Language::Portuguese;
    }
    if (lower == "en" || lower == "en-us" || lower == "en_us" ||
        lower == "english") {
        return Language::English;
    }
    return Language::Custom;
}

std::string_view language_code(Language language) noexcept {
    switch (language) {
        case Language::Portuguese:
            return "pt-BR";
        case Language::Custom:
            return g_current_language_code;
        case Language::English:
        default:
            return "en";
    }
}

std::string_view tr(Key key) noexcept {
    if (!g_initialized) {
        // Safe default on cold call before run()
        set_language(Language::English);
    }
    const auto index = static_cast<std::size_t>(key);
    if (index >= KEY_COUNT) {
        return "";
    }
    return g_current_strings[index];
}

bool load_custom_catalog(std::string_view json_content) {
    auto map = parse_catalog(json_content);
    if (map.empty()) {
        return false;
    }
    g_current_language = Language::Custom;
    populate_strings_from_map(map);
    return true;
}

std::vector<std::string> extract_language_argument(
    int argc, char* argv[]) noexcept {
    std::vector<std::string> sanitized;
    sanitized.reserve(static_cast<std::size_t>(argc));

    for (int i = 0; i < argc; ++i) {
        if (argv[i] == nullptr) {
            continue;
        }
        std::string_view arg{argv[i]};
        if (arg == "--lang") {
            if (i + 1 < argc && argv[i + 1] != nullptr) {
                set_language(argv[i + 1]);
                ++i;
            }
        } else if (arg.starts_with("--lang=")) {
            set_language(arg.substr(7));
        } else {
            sanitized.emplace_back(argv[i]);
        }
    }
    return sanitized;
}

void init_language(int argc, char* argv[]) noexcept {
    // 1. Default is English
    set_language(Language::English);

    // 2. Check environment variable KASUMI_LANG
    if (const char* env_lang = std::getenv("KASUMI_LANG")) {
        set_language(env_lang);
    }

    // 3. Command-line flags override environment variable
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == nullptr) {
            continue;
        }
        std::string_view arg{argv[i]};
        if (arg == "--lang") {
            if (i + 1 < argc && argv[i + 1] != nullptr) {
                set_language(argv[i + 1]);
                break;
            }
        } else if (arg.starts_with("--lang=")) {
            set_language(arg.substr(7));
            break;
        }
    }
}

} // namespace kasumi::cli::i18n
