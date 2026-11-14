#include "cli/wizard.hpp"

#include "application/profile.hpp"
#include "cli/credentials.hpp"
#include "cli/i18n.hpp"
#include "cli/style.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <iostream>
#include <print>
#include <string>

namespace kasumi::cli {

int run_config_wizard(const application::ExecutionEnvironment& environment) {
    const auto print_status =
        [](std::string_view color, i18n::Key label, std::string_view message) {
            std::println(
                "{}{}{} {}", color, i18n::tr(label), style::reset, message);
        };
    const auto print_error = [&](std::string_view message) {
        print_status(style::red, i18n::Key::LabelError, message);
    };
    const auto print_ok = [&](std::string_view message) {
        print_status(style::green, i18n::Key::LabelOk, message);
    };
    const auto prompt_line = [](std::string_view label, std::string& value) {
        std::print("{}", label);
        if (platform::cancellation::requested()) {
            return false;
        }
        if (!std::getline(std::cin, value)) {
            platform::cancellation::request();
            return false;
        }
        std::println("");
        return !platform::cancellation::requested();
    };
    const auto report_result =
        [&](const std::expected<void, application::ProfileError>& result,
            std::string_view ok_message) {
            if (result) {
                print_ok(ok_message);
            } else {
                print_error(result.error().detail);
            }
        };

    while (!platform::cancellation::requested()) {
        auto profiles_res = application::list_profiles(environment);
        if (!profiles_res) {
            print_error(
                std::string{i18n::tr(i18n::Key::WizardConfigReadFailed)} +
                profiles_res.error().detail);
            return 1;
        }
        std::vector<application::Profile> profiles = std::move(*profiles_res);

        std::println("{}", i18n::tr(i18n::Key::WizardHeader));
        if (profiles.empty()) {
            std::println("{}", i18n::tr(i18n::Key::WizardNoProfiles));
        } else {
            for (const auto& prof : profiles) {
                const auto state = application::inspect_profile_local_state(
                    environment, prof.name);
                i18n::println(i18n::Key::WizardProfileListEntry,
                              prof.name,
                              application::to_string(state),
                              platform::path::to_utf8(prof.local_dir),
                              prof.remote_dir);
            }
        }

        std::string choice;
        if (!prompt_line(i18n::tr(i18n::Key::WizardMenu), choice)) {
            break;
        }

        if (choice == "q" || choice == "Q") {
            break;
        } else if (choice == "n" || choice == "N") {
            std::string new_profile, new_local, new_remote;
            if (!prompt_line(i18n::tr(i18n::Key::WizardPromptProfileName),
                             new_profile)) {
                break;
            }
            if (std::ranges::any_of(profiles, [&](const auto& profile) {
                    return profile.name == new_profile;
                })) {
                print_error(i18n::format(i18n::Key::WizardProfileAlreadyExists,
                                         new_profile));
                continue;
            }

            if (!prompt_line(i18n::tr(i18n::Key::WizardPromptLocalPath),
                             new_local) ||
                !prompt_line(i18n::tr(i18n::Key::WizardPromptRemotePath),
                             new_remote)) {
                break;
            }
            if (!platform::path::from_utf8(new_local).is_absolute()) {
                print_error(i18n::tr(i18n::Key::WizardLocalPathMustBeAbsolute));
                continue;
            }
            if (new_remote.find(':') == std::string::npos &&
                !platform::path::from_utf8(new_remote).is_absolute()) {
                print_error(
                    i18n::tr(i18n::Key::WizardRemotePathMustBeAbsolute));
                continue;
            }

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

        } else if (choice == "c" || choice == "C") {
            std::string source, new_name;
            if (!prompt_line(i18n::tr(i18n::Key::WizardPromptSourceProfile),
                             source) ||
                !prompt_line(i18n::tr(i18n::Key::WizardPromptNewProfileName),
                             new_name)) {
                break;
            }
            report_result(
                application::clone_profile(environment, source, new_name),
                i18n::format(i18n::Key::WizardProfileCloned, new_name, source));

        } else if (choice == "d" || choice == "D") {
            std::string target;
            if (!prompt_line(i18n::tr(i18n::Key::WizardPromptProfileToDelete),
                             target)) {
                break;
            }
            report_result(
                application::delete_profile(environment, target),
                i18n::format(i18n::Key::WizardProfileDeleted, target));

        } else if (choice == "e" || choice == "E") {
            std::string target;
            if (!prompt_line(i18n::tr(i18n::Key::WizardPromptProfileToEdit),
                             target)) {
                break;
            }

            auto it = std::ranges::find_if(profiles, [&](const auto& p) {
                return p.name == target;
            });
            if (it != profiles.end()) {
                std::string new_local, new_remote;
                auto old_local = platform::path::to_utf8(it->local_dir);
                auto old_remote = it->remote_dir;

                if (!prompt_line(
                        i18n::format(i18n::Key::WizardPromptNewLocalPath,
                                     old_local),
                        new_local)) {
                    break;
                }
                if (new_local.empty()) {
                    new_local = old_local;
                }

                if (!prompt_line(
                        i18n::format(i18n::Key::WizardPromptNewRemotePath,
                                     old_remote),
                        new_remote)) {
                    break;
                }
                if (new_remote.empty()) {
                    new_remote = old_remote;
                }

                application::Profile p{target,
                                       platform::path::from_utf8(new_local),
                                       new_remote,
                                       it->min_history_depth,
                                       it->min_history_age_hours};
                report_result(
                    application::update_profile(environment, p),
                    i18n::format(i18n::Key::WizardProfileEdited, target));
            } else {
                print_error(i18n::tr(i18n::Key::WizardProfileNotFound));
            }

        } else if (choice == "r" || choice == "R") {
            std::string target, new_name;
            if (!prompt_line(i18n::tr(i18n::Key::WizardPromptProfileToRename),
                             target) ||
                !prompt_line(i18n::tr(i18n::Key::WizardPromptNewProfileName),
                             new_name)) {
                break;
            }
            report_result(
                application::rename_profile(environment, target, new_name),
                i18n::format(i18n::Key::WizardProfileRenamed, new_name));
        } else {
            print_error(i18n::tr(i18n::Key::WizardInvalidOption));
        }
    }
    return platform::cancellation::requested() ? 130 : 0;
}

} // namespace kasumi::cli
