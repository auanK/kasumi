#include "cli/i18n.hpp"

#include "cli/i18n_embedded.hpp"

#include <cctype>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::cli::i18n {
namespace {

Language g_current_language = Language::English;

bool equals_ignore_case(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            static_cast<unsigned char>(b[i])) {
            return false;
        }
    }
    return true;
}

} // namespace

Language current_language() noexcept {
    return g_current_language;
}

void set_language(Language language) noexcept {
    g_current_language = language;
}

void set_language(std::string_view code) noexcept {
    g_current_language = parse_language(code);
}

Language parse_language(std::string_view code) noexcept {
    if (equals_ignore_case(code, "pt") || equals_ignore_case(code, "pt-br") ||
        equals_ignore_case(code, "pt_br") ||
        equals_ignore_case(code, "portuguese")) {
        return Language::Portuguese;
    }
    return Language::English;
}

std::string_view language_code(Language language) noexcept {
    return language == Language::Portuguese ? "pt-BR" : "en";
}

std::string_view tr(Key key) noexcept {
    const auto index = static_cast<std::size_t>(key);
    if (index >= embedded::KEY_COUNT) {
        return "";
    }
    const auto& catalog = g_current_language == Language::Portuguese
                              ? embedded::PT_BR_STRINGS
                              : embedded::EN_STRINGS;
    return catalog[index];
}

std::vector<std::string> extract_language_argument(int argc,
                                                   char* argv[]) noexcept {
    std::vector<std::string> sanitized;
    if (argc < 1 || argv == nullptr || argv[0] == nullptr) {
        return sanitized;
    }
    sanitized.emplace_back(argv[0]);
    int command_index = 1;
    if (argc >= 3 && argv[1] != nullptr &&
        std::string_view{argv[1]} == "--lang" && argv[2] != nullptr &&
        argv[2][0] != '\0' && argv[2][0] != '-') {
        set_language(argv[2]);
        command_index = 3;
    }
    for (int index = command_index; index < argc; ++index) {
        if (argv[index] != nullptr) {
            sanitized.emplace_back(argv[index]);
        }
    }
    return sanitized;
}

void init_language(int argc, char* argv[]) noexcept {
    set_language(Language::English);
    if (const char* env_lang = std::getenv("KASUMI_LANG")) {
        set_language(env_lang);
    }
    if (argc >= 3 && argv != nullptr && argv[1] != nullptr &&
        std::string_view{argv[1]} == "--lang" && argv[2] != nullptr &&
        argv[2][0] != '\0' && argv[2][0] != '-') {
        set_language(argv[2]);
    }
}

} // namespace kasumi::cli::i18n
