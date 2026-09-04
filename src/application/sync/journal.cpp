#include "application/sync/journal.hpp"

#include "application/history_storage/publication.hpp"
#include "core/transaction/codec.hpp"
#include "platform/durability.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <fstream>
#include <limits>
#include <monocypher.h>
#include <system_error>
#include <utility>
#include <vector>

namespace kasumi::application::sync::journal {

namespace {

inline constexpr std::array<std::uint8_t, 4> journal_magic{'K', 'T', 'X', '2'};
inline constexpr std::size_t nonce_size = crypto::NONCE_SIZE;
inline constexpr std::size_t mac_size = crypto::MAC_SIZE;
inline constexpr std::size_t aad_size =
    journal_magic.size() + sizeof(std::uint64_t);
inline constexpr std::size_t header_size = aad_size + nonce_size + mac_size;

bool path_not_found(const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory;
}

void encode_u64_le(std::uint64_t value, std::uint8_t* output) noexcept {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        output[index] =
            static_cast<std::uint8_t>((value >> (index * 8)) & 0xffU);
    }
}

std::uint64_t decode_u64_le(const std::uint8_t* input) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        value |= static_cast<std::uint64_t>(input[index]) << (index * 8);
    }
    return value;
}

std::expected<void, std::string> validate_paths(const Paths& paths) {
    if (paths.final_path.empty() || paths.temporary_path.empty()) {
        return std::unexpected("caminhos do journal não podem ser vazios");
    }

    const auto final_parent = paths.final_path.parent_path().lexically_normal();
    const auto temporary_parent =
        paths.temporary_path.parent_path().lexically_normal();
    if (final_parent.empty() || final_parent != temporary_parent) {
        return std::unexpected(
            "caminhos do journal precisam compartilhar o diretório pai");
    }
    if (paths.final_path.filename().generic_string() != journal_file_name ||
        paths.temporary_path.filename().generic_string() !=
            std::string{journal_file_name} + std::string{temporary_suffix}) {
        return std::unexpected("nomes de arquivo do journal são inválidos");
    }

    const auto final_relative =
        paths.final_path.lexically_normal().lexically_relative(final_parent);
    const auto temporary_relative =
        paths.temporary_path.lexically_normal().lexically_relative(
            final_parent);
    if (final_relative.empty() || temporary_relative.empty() ||
        final_relative.has_parent_path() ||
        temporary_relative.has_parent_path()) {
        return std::unexpected(
            "arquivos do journal não estão diretamente no diretório pai");
    }
    return {};
}

std::expected<std::filesystem::file_status, std::string>
read_status(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (path_not_found(error)) {
        return std::filesystem::file_status{
            std::filesystem::file_type::not_found};
    }

    if (error) {
        return std::unexpected("não foi possível consultar '" + path.string() +
                               "': " + error.message());
    }
    return status;
}

bool missing(std::filesystem::file_status status) noexcept {
    return status.type() == std::filesystem::file_type::not_found;
}

std::expected<void, std::string>
validate_parent_directory(const std::filesystem::path& path,
                          bool allow_missing) {
    const auto parent = path.parent_path();
    auto status = read_status(parent);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status) && allow_missing) {
        return {};
    }
    if (std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_directory(*status)) {
        return std::unexpected("diretório pai do journal é inválido");
    }
    return platform::private_storage::protect_directory(parent);
}

std::expected<void, std::string>
validate_file_or_absent(const std::filesystem::path& path,
                        std::string_view label) {
    auto status = read_status(path);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status)) {
        return {};
    }
    if (std::filesystem::is_symlink(*status) ||
        std::filesystem::is_directory(*status) ||
        !std::filesystem::is_regular_file(*status)) {
        return std::unexpected(std::string{label} +
                               " precisa ser arquivo regular ou estar ausente");
    }
    return platform::private_storage::protect_file(path);
}

void remove_regular_file(const std::filesystem::path& path) noexcept {
    if (path.empty() || path.parent_path().empty()) {
        return;
    }

    std::error_code error;
    const auto parent =
        std::filesystem::symlink_status(path.parent_path(), error);
    if (error || std::filesystem::is_symlink(parent) ||
        !std::filesystem::is_directory(parent)) {
        return;
    }

    error.clear();
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || !std::filesystem::is_regular_file(status) ||
        std::filesystem::is_symlink(status)) {
        return;
    }
    std::filesystem::remove(path, error);
}

void wipe_sensitive(std::vector<std::byte>& payload,
                    std::vector<std::uint8_t>& plaintext,
                    std::array<std::uint8_t, nonce_size>& nonce,
                    std::array<std::uint8_t, mac_size>& mac,
                    std::array<std::uint8_t, aad_size>& aad) noexcept {
    if (!payload.empty()) {
        crypto_wipe(payload.data(), payload.size());
    }
    if (!plaintext.empty()) {
        crypto_wipe(plaintext.data(), plaintext.size());
    }
    crypto_wipe(nonce.data(), nonce.size());
    crypto_wipe(mac.data(), mac.size());
    crypto_wipe(aad.data(), aad.size());
}

std::expected<void, std::string> validate_save_paths(const Paths& paths) {
    auto structural = validate_paths(paths);
    if (!structural) {
        return structural;
    }
    auto parent = validate_parent_directory(paths.final_path, false);
    if (!parent) {
        return parent;
    }
    auto final = validate_file_or_absent(paths.final_path, "journal final");
    if (!final) {
        return final;
    }
    auto temporary =
        validate_file_or_absent(paths.temporary_path, "journal temporário");
    if (!temporary) {
        return temporary;
    }
    return {};
}

std::expected<void, std::string>
validate_record_semantics(const transaction::Record& record) {
    if (!transaction::valid(record)) {
        return std::unexpected("registro transacional inválido");
    }
    if (!record.publication_required) {
        if (record.phase == transaction::Phase::CommitPrepared ||
            record.phase == transaction::Phase::CommitUploaded ||
            record.phase == transaction::Phase::CommitVerified ||
            record.phase == transaction::Phase::HeadPublished ||
            record.phase == transaction::Phase::HeadVerified ||
            record.phase == transaction::Phase::EpochPrepared ||
            record.phase == transaction::Phase::EpochUploaded ||
            record.phase == transaction::Phase::EpochVerified) {
            return std::unexpected(
                "fase de publicação inválida para journal local-only");
        }
        return {};
    }
    if (record.phase < transaction::Phase::CommitUploaded) {
        return {};
    }
    const history_storage::HeadReference reference{
        .commit_id = record.commit_id, .ciphertext_id = record.ciphertext_id};
    if (record.marker_id != history_storage::marker_identifier(reference)) {
        return std::unexpected("marker ID incompatível com a publicação");
    }
    return {};
}

} // namespace

std::expected<Paths, std::string>
make_paths(const std::filesystem::path& profile_directory) {
    if (profile_directory.empty()) {
        return std::unexpected("diretório de perfil não pode ser vazio");
    }
    for (const auto& component : profile_directory) {
        if (component == "." || component == "..") {
            return std::unexpected(
                "diretório de perfil não pode conter . ou ..");
        }
    }

    const auto directory = profile_directory.lexically_normal();
    if (directory.empty() || directory == "." || directory == "..") {
        return std::unexpected("diretório de perfil inválido");
    }

    Paths paths{
        .final_path =
            directory / std::filesystem::path{std::string{journal_file_name}},
        .temporary_path =
            directory / std::filesystem::path{std::string{journal_file_name} +
                                              std::string{temporary_suffix}},
    };
    auto validation = validate_paths(paths);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    return paths;
}

std::expected<transaction::Record, std::string>
create_record(std::uint64_t local_generation,
              std::uint64_t storage_generation,
              SyncPlan plan,
              bool publication_required,
              std::string observed_head_id) {
    auto id = platform::random::hex_id(transaction::transaction_id_byte_count);
    if (!id) {
        return std::unexpected(id.error());
    }
    return transaction::make_record(std::move(*id),
                                    local_generation,
                                    storage_generation,
                                    std::move(plan),
                                    publication_required,
                                    std::move(observed_head_id));
}

std::expected<void, std::string>
save_with_key(const Paths& paths,
              const transaction::Record& record,
              const crypto::Key& journal_key) {
    std::vector<std::byte> payload;
    std::vector<std::uint8_t> plaintext;
    std::array<std::uint8_t, nonce_size> nonce{};
    std::array<std::uint8_t, mac_size> mac{};
    std::array<std::uint8_t, aad_size> aad{};

    try {
        auto path_validation = validate_save_paths(paths);
        if (!path_validation) {
            return path_validation;
        }
        auto record_validation = validate_record_semantics(record);
        if (!record_validation) {
            return record_validation;
        }

        auto temporary_status = read_status(paths.temporary_path);
        if (!temporary_status) {
            return std::unexpected(temporary_status.error());
        }
        if (!missing(*temporary_status)) {
            remove_regular_file(paths.temporary_path);
            temporary_status = read_status(paths.temporary_path);
            if (!temporary_status) {
                return std::unexpected(temporary_status.error());
            }
            if (!missing(*temporary_status)) {
                return std::unexpected(
                    "não foi possível remover journal temporário anterior");
            }
        }

        const auto serialization_trace = platform::perf_trace::begin();
        auto encoded = transaction::codec::encode(record);
        platform::perf_trace::finish("journal serialization",
                                     serialization_trace);
        if (!encoded) {
            return std::unexpected(encoded.error());
        }
        payload = std::move(*encoded);
        platform::perf_trace::maximum(
            "journal record serialized bytes",
            static_cast<std::uint64_t>(payload.size()));
        const auto payload_size_value =
            static_cast<std::uintmax_t>(payload.size());
        if (payload_size_value > maximum_payload_size) {
            wipe_sensitive(payload, plaintext, nonce, mac, aad);
            return std::unexpected(
                "payload do journal excede o limite suportado");
        }
        const auto payload_size =
            static_cast<std::uint64_t>(payload_size_value);
        std::copy(journal_magic.begin(), journal_magic.end(), aad.begin());
        encode_u64_le(payload_size, aad.data() + journal_magic.size());

        auto random_result = platform::random::fill_bytes(nonce);
        if (!random_result) {
            wipe_sensitive(payload, plaintext, nonce, mac, aad);
            return std::unexpected(random_result.error());
        }

        std::vector<std::uint8_t> ciphertext(payload.size());
        const auto encryption_trace = platform::perf_trace::begin();
        crypto_aead_lock(ciphertext.data(),
                         mac.data(),
                         journal_key.data(),
                         nonce.data(),
                         aad.data(),
                         aad.size(),
                         reinterpret_cast<const std::uint8_t*>(payload.data()),
                         payload.size());
        platform::perf_trace::finish("journal encryption", encryption_trace);
        if (!payload.empty()) {
            crypto_wipe(payload.data(), payload.size());
        }

        const auto durable_write_trace = platform::perf_trace::begin();
        auto created =
            platform::private_storage::create_file(paths.temporary_path);
        if (!created) {
            wipe_sensitive(payload, plaintext, nonce, mac, aad);
            return std::unexpected(created.error());
        }
        std::ofstream output(paths.temporary_path,
                             std::ios::binary | std::ios::trunc);
        if (!output) {
            remove_regular_file(paths.temporary_path);
            wipe_sensitive(payload, plaintext, nonce, mac, aad);
            return std::unexpected(
                "não foi possível abrir journal temporário para escrita");
        }

        output.write(reinterpret_cast<const char*>(journal_magic.data()),
                     static_cast<std::streamsize>(journal_magic.size()));
        const auto encoded_size = payload_size;
        std::array<std::uint8_t, sizeof(encoded_size)> size_bytes{};
        encode_u64_le(encoded_size, size_bytes.data());
        output.write(reinterpret_cast<const char*>(size_bytes.data()),
                     static_cast<std::streamsize>(size_bytes.size()));
        output.write(reinterpret_cast<const char*>(nonce.data()),
                     static_cast<std::streamsize>(nonce.size()));
        output.write(reinterpret_cast<const char*>(mac.data()),
                     static_cast<std::streamsize>(mac.size()));
        output.write(reinterpret_cast<const char*>(ciphertext.data()),
                     static_cast<std::streamsize>(ciphertext.size()));
        if (!output) {
            output.close();
            remove_regular_file(paths.temporary_path);
            crypto_wipe(nonce.data(), nonce.size());
            crypto_wipe(mac.data(), mac.size());
            crypto_wipe(aad.data(), aad.size());
            return std::unexpected("falha ao escrever journal temporário");
        }
        output.flush();
        if (!output) {
            output.close();
            remove_regular_file(paths.temporary_path);
            crypto_wipe(nonce.data(), nonce.size());
            crypto_wipe(mac.data(), mac.size());
            crypto_wipe(aad.data(), aad.size());
            return std::unexpected("falha ao descarregar journal temporário");
        }
        output.close();
        if (output.fail()) {
            remove_regular_file(paths.temporary_path);
            crypto_wipe(nonce.data(), nonce.size());
            crypto_wipe(mac.data(), mac.size());
            crypto_wipe(aad.data(), aad.size());
            return std::unexpected("falha ao fechar journal temporário");
        }

        crypto_wipe(nonce.data(), nonce.size());
        crypto_wipe(mac.data(), mac.size());
        crypto_wipe(aad.data(), aad.size());

        auto synced = platform::durability::sync_file(paths.temporary_path);
        if (!synced) {
            remove_regular_file(paths.temporary_path);
            return synced;
        }
        auto replaced = platform::durability::replace_atomically(
            paths.temporary_path, paths.final_path);
        if (!replaced) {
            remove_regular_file(paths.temporary_path);
            return replaced;
        }
        auto parent_synced =
            platform::durability::sync_parent_directory(paths.final_path);
        platform::perf_trace::finish("journal durable write",
                                     durable_write_trace);
        return parent_synced;
    } catch (const std::exception& exception) {
        remove_regular_file(paths.temporary_path);
        wipe_sensitive(payload, plaintext, nonce, mac, aad);
        return std::unexpected(std::string{"falha ao salvar journal: "} +
                               exception.what());
    }
}

std::expected<void, std::string>
save(const Paths& paths,
     const transaction::Record& record,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto journal_key = crypto::derive_key(key, crypto::KeyPurpose::Journal);
    auto result = save_with_key(paths, record, journal_key);
    crypto_wipe(journal_key.data(), journal_key.size());
    return result;
}

std::expected<std::optional<transaction::Record>, std::string>
load_with_key(const Paths& paths, const crypto::Key& journal_key) {
    std::vector<std::byte> payload;
    std::vector<std::uint8_t> plaintext;
    std::array<std::uint8_t, nonce_size> nonce{};
    std::array<std::uint8_t, mac_size> mac{};
    std::array<std::uint8_t, aad_size> aad{};

    try {
        auto structural = validate_paths(paths);
        if (!structural) {
            return std::unexpected(structural.error());
        }
        auto parent = validate_parent_directory(paths.final_path, true);
        if (!parent) {
            return std::unexpected(parent.error());
        }
        auto parent_status = read_status(paths.final_path.parent_path());
        if (!parent_status) {
            return std::unexpected(parent_status.error());
        }
        if (missing(*parent_status)) {
            return std::optional<transaction::Record>{};
        }

        auto final_status = read_status(paths.final_path);
        if (!final_status) {
            return std::unexpected(final_status.error());
        }
        if (missing(*final_status)) {
            return std::optional<transaction::Record>{};
        }
        if (std::filesystem::is_symlink(*final_status) ||
            !std::filesystem::is_regular_file(*final_status)) {
            return std::unexpected("journal final não é um arquivo regular");
        }

        std::error_code size_error;
        const auto file_size =
            std::filesystem::file_size(paths.final_path, size_error);
        if (size_error) {
            return std::unexpected(
                "não foi possível obter tamanho do journal: " +
                size_error.message());
        }
        if (file_size < header_size ||
            file_size > header_size + maximum_payload_size ||
            file_size > std::numeric_limits<std::size_t>::max()) {
            return std::unexpected("tamanho do journal inválido");
        }

        std::vector<std::uint8_t> file_data(
            static_cast<std::size_t>(file_size));
        std::ifstream input(paths.final_path, std::ios::binary);
        if (!input) {
            return std::unexpected("não foi possível abrir o journal");
        }
        input.read(reinterpret_cast<char*>(file_data.data()),
                   static_cast<std::streamsize>(file_data.size()));
        const bool incomplete =
            input.gcount() != static_cast<std::streamsize>(file_data.size()) ||
            input.bad();
        if (incomplete) {
            input.clear();
            input.close();
            if (input.fail()) {
                return std::unexpected("falha ao fechar o journal");
            }
            return std::unexpected("leitura incompleta do journal");
        }

        char extra = 0;
        input.clear();
        input.read(&extra, 1);
        const auto extra_bytes = input.gcount();
        const bool read_error = input.bad() || (!input.eof() && input.fail());
        input.clear();
        input.close();
        if (input.fail()) {
            return std::unexpected("falha ao fechar o journal");
        }
        if (read_error) {
            return std::unexpected("erro ao ler o journal");
        }
        if (extra_bytes != 0) {
            return std::unexpected("journal contém bytes excedentes");
        }

        if (!std::equal(journal_magic.begin(),
                        journal_magic.end(),
                        file_data.begin())) {
            return std::unexpected("magic do journal inválido");
        }

        std::copy_n(file_data.begin(), aad.size(), aad.begin());
        const auto decoded_size =
            decode_u64_le(file_data.data() + journal_magic.size());
        if (decoded_size > maximum_payload_size ||
            decoded_size != file_data.size() - header_size) {
            return std::unexpected("tamanho do payload do journal inválido");
        }

        std::copy_n(file_data.data() + aad.size(), nonce.size(), nonce.begin());
        std::copy_n(file_data.data() + aad.size() + nonce.size(),
                    mac.size(),
                    mac.begin());
        plaintext.resize(static_cast<std::size_t>(decoded_size));

        if (crypto_aead_unlock(plaintext.data(),
                               mac.data(),
                               journal_key.data(),
                               nonce.data(),
                               aad.data(),
                               aad.size(),
                               file_data.data() + header_size,
                               static_cast<std::size_t>(decoded_size)) != 0) {
            wipe_sensitive(payload, plaintext, nonce, mac, aad);
            return std::unexpected("autenticação do journal falhou");
        }

        auto decoded = transaction::codec::decode(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(plaintext.data()),
            plaintext.size()));
        wipe_sensitive(payload, plaintext, nonce, mac, aad);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        auto semantic_validation = validate_record_semantics(*decoded);
        if (!semantic_validation) {
            return std::unexpected(semantic_validation.error());
        }
        return std::optional<transaction::Record>{std::move(*decoded)};
    } catch (const std::exception& exception) {
        wipe_sensitive(payload, plaintext, nonce, mac, aad);
        return std::unexpected(std::string{"falha ao carregar journal: "} +
                               exception.what());
    }
}

std::expected<std::optional<transaction::Record>, std::string>
load(const Paths& paths, std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto journal_key = crypto::derive_key(key, crypto::KeyPurpose::Journal);
    auto result = load_with_key(paths, journal_key);
    crypto_wipe(journal_key.data(), journal_key.size());
    return result;
}

std::expected<void, std::string> clear(const Paths& paths) {
    auto structural = validate_paths(paths);
    if (!structural) {
        return structural;
    }
    auto parent = validate_parent_directory(paths.final_path, true);
    if (!parent) {
        return parent;
    }

    auto parent_status = read_status(paths.final_path.parent_path());
    if (!parent_status) {
        return std::unexpected(parent_status.error());
    }
    if (missing(*parent_status)) {
        return {};
    }

    auto status = read_status(paths.final_path);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status)) {
        return {};
    }
    if (std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_regular_file(*status)) {
        return std::unexpected("journal final não é um arquivo regular");
    }

    std::error_code error;
    if (!std::filesystem::remove(paths.final_path, error) || error) {
        return std::unexpected(
            "não foi possível remover journal: " +
            (error ? error.message() : std::string{"arquivo ausente"}));
    }
    return platform::durability::sync_parent_directory(paths.final_path);
}

void discard_temporary(const Paths& paths) noexcept {
    if (!validate_paths(paths)) {
        return;
    }
    auto parent = validate_parent_directory(paths.temporary_path, true);
    if (!parent) {
        return;
    }
    remove_regular_file(paths.temporary_path);
}

} // namespace kasumi::application::sync::journal
