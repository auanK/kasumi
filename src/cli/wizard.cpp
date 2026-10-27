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
    const auto read_input = [](std::string& value) {
        if (platform::cancellation::requested())
            return false;
        if (!std::getline(std::cin, value)) {
            platform::cancellation::request();
            return false;
        }
        return !platform::cancellation::requested();
    };
    while (!platform::cancellation::requested()) {
        auto profiles_res = application::list_profiles(environment);
        if (!profiles_res) {
            std::println("{}{}{} {}{}",
                         style::red,
                         i18n::tr(i18n::Key::LabelError),
                         style::reset,
                         i18n::tr(i18n::Key::WizardConfigReadFailed),
                         profiles_res.error().detail);
            return 1;
        }
        std::vector<application::Profile> profiles = std::move(*profiles_res);

        std::println("{}", i18n::tr(i18n::Key::WizardHeader));
        if (profiles.empty()) {
            std::println("{}", i18n::tr(i18n::Key::WizardNoProfiles));
        } else {
            for (const auto& prof : profiles) {
                i18n::println(i18n::Key::WizardProfileListEntry,
                              prof.name,
                              platform::path::to_utf8(prof.local_dir),
                              prof.remote_dir);
            }
        }

        std::print("{}", i18n::tr(i18n::Key::WizardMenu));
        std::string choice;
        if (!read_input(choice))
            break;
        std::println("");

        if (choice == "q" || choice == "Q") {
            break;
        } else if (choice == "n" || choice == "N") {
            std::string new_profile, new_local, new_remote;
            std::print("{}", i18n::tr(i18n::Key::WizardPromptProfileName));
            if (!read_input(new_profile))
                break;
            std::println("");
            if (std::ranges::any_of(profiles, [&](const auto& profile) {
                    return profile.name == new_profile;
                })) {
                std::println("{}{}{} {}",
                             style::red,
                             i18n::tr(i18n::Key::LabelError),
                             style::reset,
                             i18n::format(i18n::Key::WizardProfileAlreadyExists,
                                          new_profile));
                continue;
            }

            std::print("{}", i18n::tr(i18n::Key::WizardPromptLocalPath));
            if (!read_input(new_local))
                break;
            std::println("");
            std::print("{}", i18n::tr(i18n::Key::WizardPromptRemotePath));
            if (!read_input(new_remote))
                break;
            std::println("");
            if (!platform::path::from_utf8(new_local).is_absolute()) {
                std::println(
                    "{}{}{} {}",
                    style::red,
                    i18n::tr(i18n::Key::LabelError),
                    style::reset,
                    i18n::tr(i18n::Key::WizardLocalPathMustBeAbsolute));
                continue;
            }
            if (new_remote.find(':') == std::string::npos &&
                !platform::path::from_utf8(new_remote).is_absolute()) {
                std::println(
                    "{}{}{} {}",
                    style::red,
                    i18n::tr(i18n::Key::LabelError),
                    style::reset,
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
            if (!res) {
                std::println("{}{}{} {}",
                             style::red,
                             i18n::tr(i18n::Key::LabelError),
                             style::reset,
                             res.error().detail);
                continue;
            }

            std::println("{}{}{} {}",
                         style::green,
                         i18n::tr(i18n::Key::LabelOk),
                         style::reset,
                         i18n::tr(i18n::Key::WizardProfileCreated));

        } else if (choice == "c" || choice == "C") {
            std::print("{}", i18n::tr(i18n::Key::WizardPromptSourceProfile));
            std::string source;
            if (!read_input(source))
                break;
            std::println("");

            std::print("{}", i18n::tr(i18n::Key::WizardPromptNewProfileName));
            std::string new_name;
            if (!read_input(new_name))
                break;
            std::println("");

            auto res = application::clone_profile(environment, source, new_name);
            if (res) {
                std::println(
                    "{}{}{} {}",
                    style::green,
                    i18n::tr(i18n::Key::LabelOk),
                    style::reset,
                    i18n::format(i18n::Key::WizardProfileCloned, new_name, source));
            } else {
                std::println("{}{}{} {}",
                             style::red,
                             i18n::tr(i18n::Key::LabelError),
                             style::reset,
                             res.error().detail);
            }

        } else if (choice == "d" || choice == "D") {
            std::print("{}", i18n::tr(i18n::Key::WizardPromptProfileToDelete));
            std::string target;
            if (!read_input(target))
                break;
            std::println("");

            auto res = application::delete_profile(environment, target);
            if (res) {
                std::println(
                    "{}{}{} {}",
                    style::green,
                    i18n::tr(i18n::Key::LabelOk),
                    style::reset,
                    i18n::format(i18n::Key::WizardProfileDeleted, target));
            } else {
                std::println("{}{}{} {}",
                             style::red,
                             i18n::tr(i18n::Key::LabelError),
                             style::reset,
                             res.error().detail);
            }

        } else if (choice == "e" || choice == "E") {
            std::print("{}", i18n::tr(i18n::Key::WizardPromptProfileToEdit));
            std::string target;
            if (!read_input(target))
                break;
            std::println("");

            auto it = std::ranges::find_if(profiles, [&](const auto& p) {
                return p.name == target;
            });
            if (it != profiles.end()) {
                std::string new_local, new_remote;
                auto old_local = platform::path::to_utf8(it->local_dir);
                auto old_remote = it->remote_dir;

                i18n::print(i18n::Key::WizardPromptNewLocalPath, old_local);
                if (!read_input(new_local))
                    break;
                std::println("");
                if (new_local.empty())
                    new_local = old_local;

                i18n::print(i18n::Key::WizardPromptNewRemotePath, old_remote);
                if (!read_input(new_remote))
                    break;
                std::println("");
                if (new_remote.empty())
                    new_remote = old_remote;

                application::Profile p{target,
                                       platform::path::from_utf8(new_local),
                                       new_remote,
                                       it->min_history_depth,
                                       it->min_history_age_hours};
                auto res = application::update_profile(environment, p);
                if (res) {
                    std::println(
                        "{}{}{} {}",
                        style::green,
                        i18n::tr(i18n::Key::LabelOk),
                        style::reset,
                        i18n::format(i18n::Key::WizardProfileEdited, target));
                } else {
                    std::println("{}{}{} {}",
                                 style::red,
                                 i18n::tr(i18n::Key::LabelError),
                                 style::reset,
                                 res.error().detail);
                }
            } else {
                std::println("{}{}{} {}",
                             style::red,
                             i18n::tr(i18n::Key::LabelError),
                             style::reset,
                             i18n::tr(i18n::Key::WizardProfileNotFound));
            }

        } else if (choice == "r" || choice == "R") {
            std::print("{}", i18n::tr(i18n::Key::WizardPromptProfileToRename));
            std::string target;
            if (!read_input(target))
                break;
            std::println("");

            std::print("{}", i18n::tr(i18n::Key::WizardPromptNewProfileName));
            std::string new_name;
            if (!read_input(new_name))
                break;
            std::println("");

            auto res =
                application::rename_profile(environment, target, new_name);
            if (res) {
                std::println(
                    "{}{}{} {}",
                    style::green,
                    i18n::tr(i18n::Key::LabelOk),
                    style::reset,
                    i18n::format(i18n::Key::WizardProfileRenamed, new_name));
            } else {
                std::println("{}{}{} {}",
                             style::red,
                             i18n::tr(i18n::Key::LabelError),
                             style::reset,
                             res.error().detail);
            }
        } else {
            std::println("{}{}{} {}",
                         style::red,
                         i18n::tr(i18n::Key::LabelError),
                         style::reset,
                         i18n::tr(i18n::Key::WizardInvalidOption));
        }
    }
    return platform::cancellation::requested() ? 130 : 0;
}

} // namespace kasumi::cli
