#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "transport/transport.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace {

using kasumi::test::TempWorkspace;
using kasumi::transport::ErrorCode;
using kasumi::transport::Presence;
using kasumi::transport::Removal;
using kasumi::transport::Transport;

TEST(LocalTransportTest, InitializesStorageAndComposesValidOperations) {
    auto workspace =
        kasumi::test::make_temp_workspace("transport-local-initialize");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& transport = *opened;

    EXPECT_TRUE(kasumi::transport::valid(transport));
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    EXPECT_TRUE(std::filesystem::is_directory(
        kasumi::test::workspace_path(workspace, "storage")));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "storage/control")));
}

TEST(LocalTransportTest, StoresListsAndRemovesObjects) {
    auto workspace =
        kasumi::test::make_temp_workspace("transport-local-storage");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& transport = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto source_a = kasumi::test::workspace_path(workspace, "a.bin");
    const auto source_b = kasumi::test::workspace_path(workspace, "b.bin");
    const auto destination =
        kasumi::test::workspace_path(workspace, "destination.bin");
    kasumi::test::write_text(source_a, "first");
    kasumi::test::write_text(source_b, "second");

    ASSERT_TRUE(kasumi::transport::put(transport, source_a, "zeta"));
    ASSERT_TRUE(kasumi::transport::put(transport, source_b, "alpha"));
    ASSERT_EQ(kasumi::transport::presence(transport, "alpha").value(),
              Presence::Present);
    ASSERT_EQ(kasumi::transport::list(transport).value(),
              (std::vector<std::string>{"alpha", "zeta"}));

    ASSERT_TRUE(kasumi::transport::get(transport, "alpha", destination));
    EXPECT_EQ(kasumi::test::read_text(destination), "second");
    ASSERT_EQ(kasumi::transport::remove(transport, "alpha").value(),
              Removal::Removed);
    EXPECT_EQ(kasumi::transport::remove(transport, "alpha").value(),
              Removal::AlreadyAbsent);
}

TEST(LocalTransportTest, ListsOnlyDirectFilesUnderValidatedPrefix) {
    auto workspace =
        kasumi::test::make_temp_workspace("transport-local-prefix");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& transport = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto source = kasumi::test::workspace_path(workspace, "object.bin");
    kasumi::test::write_text(source, "object");
    ASSERT_TRUE(
        kasumi::transport::put(transport, source, "history/heads/a.head"));
    ASSERT_TRUE(
        kasumi::transport::put(transport, source, "history/heads/b.head"));
    ASSERT_TRUE(kasumi::transport::put(transport,
                                       source,
                                       "history/commits/"
                                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                       "aaaaaaaaaaaaaaaaaaaaaaaaa/a.kcom"));
    ASSERT_TRUE(kasumi::transport::put(transport, source, "irrelevant"));

    EXPECT_EQ(kasumi::transport::list(transport, "history/heads").value(),
              (std::vector<std::string>{"a.head", "b.head"}));
    EXPECT_EQ(
        kasumi::transport::list(
            transport,
            "history/commits/"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .value(),
        (std::vector<std::string>{"a.kcom"}));
    EXPECT_EQ(
        kasumi::transport::list(transport, "history/heads/a.head").error().code,
        ErrorCode::StorageNotFound);
    EXPECT_EQ(kasumi::transport::list(transport, "../history").error().code,
              ErrorCode::InvalidIdentifier);
}

TEST(LocalTransportTest, RejectsInvalidContextsAndIdentifiers) {
    auto workspace =
        kasumi::test::make_temp_workspace("transport-local-validation");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& transport = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    for (const auto identifier :
         {"../escape", "/absolute", ".", "segment/../escape", "a\\b"}) {
        const auto result = kasumi::transport::presence(transport, identifier);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, ErrorCode::InvalidIdentifier);
    }

    Transport invalid{};
    const auto result = kasumi::transport::list(invalid);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidContext);
}

TEST(LocalTransportTest, RejectsRelativeStoragePath) {
    const auto result = kasumi::transport::open_transport("relative");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidContext);
}

TEST(LocalTransportTest, RejectsStorageBelowRegularFile) {
    auto workspace =
        kasumi::test::make_temp_workspace("transport-local-file-root");
    const auto file = kasumi::test::workspace_path(workspace, "file");
    kasumi::test::write_text(file, "content");

    const auto result =
        kasumi::transport::open_transport((file / "storage").string());

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidContext);
}

#if defined(_WIN32)
TEST(LocalTransportTest, RejectsUnavailableDrive) {
    std::filesystem::path unavailable;
    for (char letter = 'Z'; letter >= 'D'; --letter) {
        const std::filesystem::path root{std::string{letter} + ":/"};
        std::error_code error;
        if (!std::filesystem::exists(root, error)) {
            unavailable = root;
            break;
        }
    }
    if (unavailable.empty()) {
        GTEST_SKIP() << "no unavailable drive letter";
    }

    const auto result =
        kasumi::transport::open_transport((unavailable / "kasumi").string());

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::StorageNotFound);
}
#endif

TEST(LocalTransportTest, PutBatchFallbackAndValidation) {
    auto workspace = kasumi::test::make_temp_workspace("transport-local-batch");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& transport = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto source_root = kasumi::test::workspace_path(workspace, "batch");
    std::filesystem::create_directories(source_root);
    kasumi::test::write_text(source_root / "a", "alpha");
    kasumi::test::write_text(source_root / "b", "beta");

    // Teste 1 - batch vazio
    const auto empty_root = kasumi::test::workspace_path(workspace, "empty-batch");
    std::filesystem::create_directories(empty_root);
    kasumi::transport::PutBatch empty_batch{.source_root = empty_root, .identifiers = {}};
    EXPECT_TRUE(kasumi::transport::put_batch(transport, empty_batch).has_value());

    // Teste 3 - múltiplos arquivos
    kasumi::transport::PutBatch valid_batch{.source_root = source_root, .identifiers = {"a", "b"}};
    EXPECT_TRUE(kasumi::transport::put_batch(transport, valid_batch).has_value());
    EXPECT_EQ(kasumi::transport::presence(transport, "a").value(), Presence::Present);
    EXPECT_EQ(kasumi::transport::presence(transport, "b").value(), Presence::Present);

    // Teste 4 - identifier duplicado
    kasumi::transport::PutBatch duplicate_batch{.source_root = source_root, .identifiers = {"a", "a"}};
    EXPECT_FALSE(kasumi::transport::put_batch(transport, duplicate_batch).has_value());

    // Teste 5 - path traversal
    kasumi::transport::PutBatch traversal_batch{.source_root = source_root, .identifiers = {"../a"}};
    EXPECT_FALSE(kasumi::transport::put_batch(transport, traversal_batch).has_value());

    // Teste 6 - arquivo ausente
    kasumi::transport::PutBatch missing_batch{.source_root = source_root, .identifiers = {"a", "c"}};
    EXPECT_FALSE(kasumi::transport::put_batch(transport, missing_batch).has_value());

    // Teste 7 - arquivo inesperado
    kasumi::test::write_text(source_root / "unexpected", "surprise");
    EXPECT_FALSE(kasumi::transport::put_batch(transport, valid_batch).has_value());
    std::filesystem::remove(source_root / "unexpected");

    // Teste 8 - symlink (somente se suportado, fallback seguro via omitir no Windows se der erro)
    std::error_code ec;
    std::filesystem::create_symlink(source_root / "a", source_root / "symlink", ec);
    if (!ec) {
        kasumi::transport::PutBatch symlink_batch{.source_root = source_root, .identifiers = {"a", "symlink"}};
        EXPECT_FALSE(kasumi::transport::put_batch(transport, symlink_batch).has_value());
        std::filesystem::remove(source_root / "symlink");
    }
}

TEST(LocalTransportTest, GetBatchFallsBackAndValidatesIdentifiers) {
    auto workspace =
        kasumi::test::make_temp_workspace("transport-local-get-batch");
    const auto storage_root =
        kasumi::test::workspace_path(workspace, "storage");
    auto opened = kasumi::transport::open_transport(storage_root.string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));

    kasumi::test::write_text(storage_root / "nested/object", "payload");

    const auto destination =
        kasumi::test::workspace_path(workspace, "destination");
    std::filesystem::create_directories(destination);
    EXPECT_TRUE(kasumi::transport::get_batch(*opened,
                                             {.source_prefix = "nested",
                                              .destination_root = destination,
                                              .identifiers = {"object"}}));
    EXPECT_EQ(kasumi::test::read_text(destination / "object"), "payload");

    EXPECT_FALSE(
        kasumi::transport::get_batch(*opened,
                                     {.source_prefix = "nested",
                                      .destination_root = destination,
                                      .identifiers = {"object", "object"}}));
    EXPECT_FALSE(kasumi::transport::get_batch(*opened,
                                              {.source_prefix = "nested",
                                               .destination_root = destination,
                                               .identifiers = {"../object"}}));
    EXPECT_FALSE(kasumi::transport::get_batch(*opened,
                                              {.source_prefix = "../nested",
                                               .destination_root = destination,
                                               .identifiers = {"object"}}));
}

TEST(LocalTransportTest, PhysicalHashBatchIsUnsupportedWithoutCapability) {
    auto workspace =
        kasumi::test::make_temp_workspace("transport-local-bulk-hash");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));

    kasumi::transport::PhysicalHashBatchRequest request{
        .scratch_root = kasumi::test::workspace_root(workspace),
        .objects = {{"a", std::string(64, 'a')}},
        .algorithm = "sha256",
    };
    const auto result =
        kasumi::transport::physical_hash_batch(*opened, request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::Unsupported);
}

TEST(LocalTransportTest, ControlReadBatchIsUnsupportedWithoutCapability) {
    auto workspace =
        kasumi::test::make_temp_workspace("transport-local-control-batch");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));

    kasumi::transport::ControlReadBatchRequest request{
        .list_prefixes = {"history/gc/v1/writers"},
        .presence_identifiers = {"history/gc/v1/barrier"},
    };
    const auto result = kasumi::transport::control_read_batch(*opened, request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::Unsupported);
}

} // namespace
