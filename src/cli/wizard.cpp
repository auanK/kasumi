#include "cli/wizard.hpp"

#include "application/profile.hpp"
#include "cli/credentials.hpp"
#include "cli/i18n.hpp"
#include "cli/style.hpp"
#include "platform/cancellation.hpp"

#include <algorithm>
#include <iostream>
#include <print>
#include <string>

namespace kasumi::cli {

void run_config_wizard(const application::ExecutionEnvironment& environment) {
    while (true) {
        auto profiles_res = application::list_profiles(environment);
        if (!profiles_res) {
            std::println("{}{}{} {}{}",
                         style::red,
                         i18n::tr(i18n::Key::LabelError),
                         style::reset,
                         i18n::tr(i18n::Key::WizardConfigReadFailed),
                         profiles_res.error().detail);
            break;
        }
        std::vector<application::Profile> profiles = std::move(*profiles_res);

        std::println("{}", i18n::tr(i18n::Key::WizardHeader));
        if (profiles.empty()) {
            std::println("{}", i18n::tr(i18n::Key::WizardNoProfiles));
        } else {
            for (const auto& prof : profiles) {
                std::println("- {}  [ Local: {} | Destino: {} ]",
                             prof.name,
                             prof.local_dir.string(),
                             prof.remote_dir);
            }
        }

        std::print("{}", i18n::tr(i18n::Key::WizardMenu));
        std::string choice;
        if (!std::getline(std::cin, choice))
            break;
        std::println("");

        if (choice == "q" || choice == "Q") {
            break;
        } else if (choice == "n" || choice == "N") {
            std::string new_profile, new_local, new_remote;
            std::print("{}", i18n::tr(i18n::Key::WizardPromptProfileName));
            std::getline(std::cin, new_profile);
            std::println("");
            if (std::ranges::any_of(profiles, [&](const auto& profile) {
                    return profile.name == new_profile;
                })) {
                std::println("{}{}{} {}",
                             style::red,
                             i18n::tr(i18n::Key::LabelError),
                             style::reset,
                             i18n::format(i18n::Key::WizardProfileAlreadyExists, new_profile));
                continue;
            }

            std::print("{}", i18n::tr(i18n::Key::WizardPromptLocalPath));
            std::getline(std::cin, new_local);
            std::println("");
            std::print("{}", i18n::tr(i18n::Key::WizardPromptRemotePath));
            std::getline(std::cin, new_remote);
            std::println("");
            if (!std::filesystem::path{new_local}.is_absolute()) {
                std::println("{}{}{} {}",
                             style::red,
                             i18n::tr(i18n::Key::LabelError),
                             style::reset,
                             i18n::tr(i18n::Key::WizardLocalPathMustBeAbsolute));
                continue;
            }
            if (new_remote.find(':') == std::string::npos &&
                !std::filesystem::path{new_remote}.is_absolute()) {
                std::println("{}{}{} {}",
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
                                       std::filesystem::path(new_local),
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

        } else if (choice == "d" || choice == "D") {
            std::print("{}", i18n::tr(i18n::Key::WizardPromptProfileToDelete));
            std::string target;
            std::getline(std::cin, target);
            std::println("");

            auto res = application::delete_profile(environment, target);
            if (res) {
                std::println("{}{}{} {}",
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
            std::getline(std::cin, target);
            std::println("");

            auto it = std::ranges::find_if(profiles, [&](const auto& p) {
                return p.name == target;
            });
            if (it != profiles.end()) {
                std::string new_local, new_remote;
                auto old_local = it->local_dir.string();
                auto old_remote = it->remote_dir;

                i18n::print(i18n::Key::WizardPromptNewLocalPath, old_local);
                std::getline(std::cin, new_local);
                std::println("");
                if (new_local.empty())
                    new_local = old_local;

                i18n::print(i18n::Key::WizardPromptNewRemotePath,
                            old_remote);
                std::getline(std::cin, new_remote);
                std::println("");
                if (new_remote.empty())
                    new_remote = old_remote;

                application::Profile p{target,
                                       std::filesystem::path(new_local),
                                       new_remote,
                                       it->min_history_depth,
                                       it->min_history_age_hours};
                auto res = application::update_profile(environment, p);
                if (res) {
                    std::println("{}{}{} {}",
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
            std::getline(std::cin, target);
            std::println("");

            std::print("{}", i18n::tr(i18n::Key::WizardPromptNewProfileName));
            std::string new_name;
            std::getline(std::cin, new_name);
            std::println("");

            auto res =
                application::rename_profile(environment, target, new_name);
            if (res) {
                std::println("{}{}{} {}",
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
}

} // namespace kasumi::cli
