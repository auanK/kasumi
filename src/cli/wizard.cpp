#include "cli/wizard.hpp"

#include "application/profile.hpp"
#include "cli/credentials.hpp"
#include "cli/i18n.hpp"
#include "cli/presenter.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <print>
#include <string>

namespace kasumi::cli {

int run_profile_query(const application::ExecutionEnvironment& environment,
                      std::string_view profile_name) {
    const auto fail_query = [](std::string_view message) {
        std::println(stderr, "{} {}", i18n::tr(i18n::Key::LabelError), message);
        return 1;
    };
    auto profiles = application::list_profiles(environment);
    if (!profiles) {
        return fail_query(profiles.error().detail);
    }
    for (const auto& profile : *profiles) {
        if (profile_name.empty()) {
            std::println("{}", profile.name);
        } else if (profile.name == profile_name) {
            application::ProfileLocalProblem problem;
            const auto state = application::inspect_profile_local_state(
                environment, profile.name, &problem);
            i18n::println(i18n::Key::WizardProfileDetails,
                          profile.name,
                          platform::path::to_utf8(profile.local_dir),
                          profile.remote_dir,
                          application::to_string(state),
                          application::to_string(profile.key_storage),
                          profile.min_history_depth,
                          profile.min_history_age_hours);
            if (state == application::ProfileLocalState::Problem) {
                static constexpr auto problem_keys = std::to_array<i18n::Key>({
                    i18n::Key::WizardProblemUnspecified,
                    i18n::Key::WizardProblemName,
                    i18n::Key::WizardProblemPaths,
                    i18n::Key::WizardProblemDirectory,
                    i18n::Key::WizardProblemKey,
                    i18n::Key::WizardProblemDatabase,
                    i18n::Key::WizardProblemLock,
                    i18n::Key::WizardProblemSidecar,
                    i18n::Key::WizardProblemJournal,
                    i18n::Key::WizardProblemWorkspace,
                    i18n::Key::WizardProblemSnapshot,
                    i18n::Key::WizardProblemCleanup,
                });
                static_assert(problem_keys.size() ==
                              static_cast<std::size_t>(
                                  application::ProfileLocalProblem::Count));
                i18n::println(
                    i18n::Key::WizardProblemReason,
                    i18n::tr(problem_keys[static_cast<std::size_t>(problem)]));
            }
            return 0;
        }
    }
    if (!profile_name.empty()) {
        return fail_query(i18n::tr(i18n::Key::WizardProfileNotFound));
    }
    return 0;
}

int run_profile_key(const application::ExecutionEnvironment& environment,
                    std::string_view profile_name) {
    auto profiles = application::list_profiles(environment);
    if (!profiles) {
        print_error_line(profiles.error().detail);
        return 1;
    }
    const auto it =
        std::ranges::find(*profiles, profile_name, &application::Profile::name);
    if (it == profiles->end()) {
        print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
        return 1;
    }
    if (it->key_storage == application::KeyStorage::Memory) {
        print_error_line(i18n::format(
            i18n::Key::WizardKeyStorageMemoryNoPersist, profile_name));
        return 1;
    }
    application::ProfileCredentials creds =
        [&]() -> application::ProfileCredentials {
        if (const char* env = std::getenv("KASUMI_MASTER_KEY")) {
            return application::MasterKeyHex{std::string(env)};
        }
        return credentials::read_password_pair();
    }();
    if (platform::cancellation::requested()) {
        application::wipe_credentials(creds);
        return 130;
    }
    auto res = application::set_profile_key(
        environment, profile_name, std::move(creds));
    application::wipe_credentials(creds);
    if (!res) {
        print_error_line(res.error().detail);
        return 1;
    }
    print_ok_line(
        i18n::format(i18n::Key::WizardProfileKeyUpdated, profile_name));
    return 0;
}

int run_config_wizard(const application::ExecutionEnvironment& environment) {
    const auto prompt_line = [](std::string_view label, std::string& value) {
        std::print("{}", label);
        if (platform::cancellation::requested()) {
            return false;
        }
        if (!std::getline(std::cin, value)) {
            platform::cancellation::request();
            return false;
        }
        return !platform::cancellation::requested();
    };
    const auto confirm_change = [&](std::string_view message) {
        std::string confirmation;
        if (!prompt_line(message, confirmation)) {
            return false;
        }
        std::ranges::transform(
            confirmation, confirmation.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
        return confirmation == "y" || confirmation == "yes" ||
               confirmation == "s" || confirmation == "sim";
    };
    const auto report_result =
        [&](const std::expected<void, application::ProfileError>& result,
            std::string_view ok_message) {
            if (result) {
                print_ok_line(ok_message);
            } else {
                print_error_line(result.error().detail);
            }
        };

    while (!platform::cancellation::requested()) {
        auto profiles_res = application::list_profiles(environment);
        if (!profiles_res) {
            print_error_line(
                std::string{i18n::tr(i18n::Key::WizardConfigReadFailed)} +
                profiles_res.error().detail);
            return 1;
        }
        std::vector<application::Profile> profiles = std::move(*profiles_res);

        i18n::println(i18n::Key::WizardHeader);
        if (profiles.empty()) {
            i18n::println(i18n::Key::WizardNoProfiles);
        } else {
            i18n::println(i18n::Key::WizardProfileListHeader);
            for (const auto& prof : profiles) {
                const auto state = application::inspect_profile_local_state(
                    environment, prof.name);
                i18n::println(i18n::Key::WizardProfileListEntry,
                              prof.name,
                              application::to_string(state));
            }
        }

        std::string choice;
        if (!prompt_line(i18n::tr(i18n::Key::WizardMenu), choice)) {
            break;
        }
        std::println();
        if (choice.size() == 1) {
            choice[0] = static_cast<char>(
                std::tolower(static_cast<unsigned char>(choice[0])));
        }

        const auto prompt_field = [&](std::string_view label,
                                      application::ProfileField field,
                                      std::string& value,
                                      std::string_view fallback = {}) {
            while (prompt_line(label, value)) {
                if (value.empty() && !fallback.empty()) {
                    value = fallback;
                }
                if (auto valid =
                        application::validate_profile_field(field, value);
                    !valid) {
                    const auto key =
                        field == application::ProfileField::Name
                            ? i18n::Key::WizardInvalidProfileName
                        : field == application::ProfileField::LocalPath
                            ? i18n::Key::WizardLocalPathMustBeAbsolute
                            : i18n::Key::WizardInvalidRemotePath;
                    print_error_line(i18n::tr(key));
                    continue;
                }
                if (field == application::ProfileField::Name &&
                    std::ranges::any_of(profiles, [&](const auto& profile) {
                        return profile.name == value;
                    })) {
                    print_error_line(i18n::format(
                        i18n::Key::WizardProfileAlreadyExists, value));
                    continue;
                }
                return true;
            }
            return false;
        };

        const auto prompt_existing = [&](i18n::Key key, std::string& name) {
            while (prompt_line(i18n::tr(key), name)) {
                if (std::ranges::find(
                        profiles, name, &application::Profile::name) !=
                    profiles.end()) {
                    return true;
                }
                print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
            }
            return false;
        };

        const auto prompt_pair = [&](i18n::Key first_key,
                                     std::string& first,
                                     std::string& second) {
            return prompt_existing(first_key, first) &&
                   prompt_field(i18n::tr(i18n::Key::WizardPromptNewProfileName),
                                application::ProfileField::Name,
                                second);
        };

        if (choice == "q") {
            break;
        } else if (choice == "n") {
            std::string new_profile, new_local, new_remote;
            if (!prompt_field(i18n::tr(i18n::Key::WizardPromptProfileName),
                              application::ProfileField::Name,
                              new_profile)) {
                break;
            }
            std::println();
            if (!prompt_field(i18n::tr(i18n::Key::WizardPromptLocalPath),
                              application::ProfileField::LocalPath,
                              new_local) ||
                !prompt_field(i18n::tr(i18n::Key::WizardPromptRemotePath),
                              application::ProfileField::RemotePath,
                              new_remote)) {
                break;
            }
            std::println();
            application::ProfileCredentials creds =
                credentials::read_password_pair();
            if (platform::cancellation::requested()) {
                application::wipe_credentials(creds);
                break;
            }

            application::Profile p{.name = new_profile,
                                   .local_dir =
                                       platform::path::from_utf8(new_local),
                                   .remote_dir = new_remote};
            auto res =
                application::create_profile(environment, p, std::move(creds));
            application::wipe_credentials(creds);
            report_result(res, i18n::tr(i18n::Key::WizardProfileCreated));
        } else if (choice == "c") {
            std::string source, new_name;
            if (!prompt_pair(
                    i18n::Key::WizardPromptSourceProfile, source, new_name)) {
                break;
            }
            report_result(
                application::clone_profile(environment, source, new_name),
                i18n::format(i18n::Key::WizardProfileCloned, new_name, source));

        } else if (choice == "d") {
            std::string target;
            if (!prompt_existing(i18n::Key::WizardPromptProfileToDelete,
                                 target)) {
                break;
            }
            const auto selected = std::ranges::find(
                profiles, target, &application::Profile::name);
            if (selected == profiles.end()) {
                print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
                continue;
            }
            if (!confirm_change(
                    i18n::format(i18n::Key::WizardConfirmDelete,
                                 selected->name,
                                 platform::path::to_utf8(selected->local_dir),
                                 selected->remote_dir))) {
                continue;
            }
            report_result(
                application::delete_profile(environment, target),
                i18n::format(i18n::Key::WizardProfileDeleted, target));

        } else if (choice == "e") {
            std::string target;
            if (!prompt_existing(i18n::Key::WizardPromptProfileToEdit,
                                 target)) {
                break;
            }

            auto it =
                std::ranges::find_if(profiles, [&](const auto& candidate) {
                    return candidate.name == target;
                });
            if (it != profiles.end()) {
                const auto prompt_default = [&](i18n::Key key,
                                                const std::string& fallback,
                                                std::string& out) {
                    return prompt_field(
                        i18n::format(key, fallback),
                        key == i18n::Key::WizardPromptNewLocalPath
                            ? application::ProfileField::LocalPath
                            : application::ProfileField::RemotePath,
                        out,
                        fallback);
                };
                std::string edit_local, edit_remote;
                if (!prompt_default(i18n::Key::WizardPromptNewLocalPath,
                                    platform::path::to_utf8(it->local_dir),
                                    edit_local) ||
                    !prompt_default(i18n::Key::WizardPromptNewRemotePath,
                                    it->remote_dir,
                                    edit_remote)) {
                    break;
                }

                application::Profile updated{
                    target,
                    platform::path::from_utf8(edit_local),
                    edit_remote,
                    it->min_history_depth,
                    it->min_history_age_hours,
                    it->key_storage};
                if (updated.local_dir == it->local_dir &&
                    updated.remote_dir == it->remote_dir) {
                    continue;
                }
                if (!confirm_change(
                        i18n::format(i18n::Key::WizardConfirmEdit,
                                     target,
                                     platform::path::to_utf8(it->local_dir),
                                     edit_local,
                                     it->remote_dir,
                                     edit_remote))) {
                    continue;
                }
                report_result(
                    application::update_profile(environment, updated),
                    i18n::format(i18n::Key::WizardProfileEdited, target));
            } else {
                print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
            }

        } else if (choice == "k") {
            std::string target;
            if (!prompt_existing(i18n::Key::WizardPromptProfileToKey, target)) {
                break;
            }
            const auto selected = std::ranges::find(
                profiles, target, &application::Profile::name);
            if (selected == profiles.end()) {
                print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
                continue;
            }
            if (selected->key_storage == application::KeyStorage::Memory) {
                print_error_line(i18n::format(
                    i18n::Key::WizardKeyStorageMemoryNoPersist, target));
                continue;
            }
            application::ProfileCredentials creds =
                credentials::read_password_pair();
            if (platform::cancellation::requested()) {
                application::wipe_credentials(creds);
                break;
            }
            auto res = application::set_profile_key(
                environment, target, std::move(creds));
            application::wipe_credentials(creds);
            report_result(
                res, i18n::format(i18n::Key::WizardProfileKeyUpdated, target));

        } else if (choice == "s") {
            std::string target;
            if (!prompt_existing(i18n::Key::WizardPromptProfileToStorage,
                                 target)) {
                break;
            }
            const auto selected = std::ranges::find(
                profiles, target, &application::Profile::name);
            if (selected == profiles.end()) {
                print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
                continue;
            }
            application::KeyStorage chosen = selected->key_storage;
            bool cancelled = false;
            const std::string prompt =
                i18n::format(i18n::Key::WizardPromptKeyStorage,
                             application::to_string(selected->key_storage));
            while (true) {
                std::string raw_mode;
                if (!prompt_line(prompt, raw_mode)) {
                    cancelled = true;
                    break;
                }
                const auto first = raw_mode.find_first_not_of(" \t\r\n");
                if (first == std::string::npos) {
                    chosen = selected->key_storage;
                    break;
                }
                const auto last = raw_mode.find_last_not_of(" \t\r\n");
                std::string mode = raw_mode.substr(first, last - first + 1);
                std::ranges::transform(mode, mode.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                if (mode == "vault") {
                    chosen = application::KeyStorage::Vault;
                    break;
                }
                if (mode == "file") {
                    chosen = application::KeyStorage::File;
                    break;
                }
                if (mode == "memory") {
                    chosen = application::KeyStorage::Memory;
                    break;
                }
                print_error_line(i18n::tr(i18n::Key::WizardInvalidKeyStorage));
            }
            if (cancelled) {
                break;
            }
            if (chosen == selected->key_storage) {
                continue;
            }
            application::Profile updated = *selected;
            updated.key_storage = chosen;
            auto res = application::update_profile(environment, updated);
            if (!res) {
                print_error_line(res.error().detail);
            } else if (chosen == application::KeyStorage::Memory) {
                print_ok_line(
                    i18n::format(i18n::Key::WizardProfileKeyStorageUpdated,
                                 target,
                                 application::to_string(chosen)));
            } else {
                print_ok_line(i18n::format(
                    i18n::Key::WizardProfileKeyStorageUpdatedNeedKey,
                    target,
                    application::to_string(chosen)));
            }

        } else if (choice == "r") {
            std::string target, new_name;
            if (!prompt_pair(
                    i18n::Key::WizardPromptProfileToRename, target, new_name)) {
                break;
            }
            report_result(
                application::rename_profile(environment, target, new_name),
                i18n::format(i18n::Key::WizardProfileRenamed, new_name));
        } else {
            print_error_line(i18n::tr(i18n::Key::WizardInvalidOption));
        }
    }
    return platform::cancellation::requested() ? 130 : 0;
}

} // namespace kasumi::cli
