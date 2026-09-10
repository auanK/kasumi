#include "core/hasher.hpp"
#include "core/node.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using kasumi::Hash;
using kasumi::NodeRow;
using kasumi::Snapshot;

NodeRow make_file(std::string path,
                  std::string_view contents,
                  std::uint64_t size,
                  std::filesystem::file_time_type modified = {}) {
    return {
        .path = std::move(path),
        .hash = kasumi::hasher::hash_string(contents),
        .size = size,
        .mtime = modified,
        .is_directory = false,
    };
}

NodeRow make_directory(std::string path,
                       std::filesystem::file_time_type modified = {}) {
    return {
        .path = std::move(path),
        .mtime = modified,
        .is_directory = true,
    };
}

std::vector<std::string> paths_of(const Snapshot& snapshot) {
    std::vector<std::string> paths;
    paths.reserve(snapshot.rows.size());
    for (const auto& row : snapshot.rows) {
        paths.push_back(row.path);
    }
    return paths;
}

TEST(NodePathTest, OrdersByComponentsAndPlacesParentsBeforeDescendants) {
    std::vector<std::string> paths{
        "team-archive/report.txt",
        "team/zeta.txt",
        "team",
        "",
        "team/alpha.txt",
        "team-archive",
    };

    std::ranges::sort(paths, kasumi::path_less);

    EXPECT_EQ(paths,
              (std::vector<std::string>{
                  "",
                  "team",
                  "team/alpha.txt",
                  "team/zeta.txt",
                  "team-archive",
                  "team-archive/report.txt",
              }));
    EXPECT_TRUE(kasumi::path_less("team", "team/alpha.txt"));
    EXPECT_FALSE(kasumi::path_less("team/alpha.txt", "team"));
    EXPECT_FALSE(kasumi::path_less("team", "team"));
}

TEST(NodePathTest, ExtractsNamesAndParentsAndHonorsComponentBoundaries) {
    EXPECT_EQ(kasumi::row_name("alpha/beta/file.txt"), "file.txt");
    EXPECT_EQ(kasumi::row_name("leaf.txt"), "leaf.txt");
    EXPECT_EQ(kasumi::row_name(""), "");

    EXPECT_EQ(kasumi::row_parent("alpha/beta/file.txt"), "alpha/beta");
    EXPECT_EQ(kasumi::row_parent("leaf.txt"), "");
    EXPECT_EQ(kasumi::row_parent(""), "");

    EXPECT_TRUE(kasumi::is_descendant("alpha/beta", "alpha"));
    EXPECT_TRUE(kasumi::is_descendant("alpha/beta/deep", "alpha/beta"));
    EXPECT_TRUE(kasumi::is_descendant("alpha", ""));
    EXPECT_FALSE(kasumi::is_descendant("", ""));
    EXPECT_FALSE(kasumi::is_descendant("alpha/beta", "alpha/beta"));
    EXPECT_FALSE(kasumi::is_descendant("alpha/betadine", "alpha/beta"));
    EXPECT_FALSE(kasumi::is_descendant("alpha/beta", "alpha/bet"));
}

TEST(SnapshotValidationTest, EnforcesTheCanonicalSnapshotShape) {
    EXPECT_TRUE(kasumi::valid_snapshot(Snapshot{}, true));
    EXPECT_FALSE(kasumi::valid_snapshot(Snapshot{}, false));

    EXPECT_TRUE(kasumi::valid_snapshot(Snapshot{{make_directory("")}}, false));
    EXPECT_FALSE(
        kasumi::valid_snapshot(Snapshot{{make_directory("folder")}}, false));
    EXPECT_FALSE(kasumi::valid_snapshot(
        Snapshot{{make_file("", "root-file", 9)}}, false));
    EXPECT_FALSE(kasumi::valid_snapshot(
        Snapshot{{make_directory(""), make_directory("")}}, false));
    EXPECT_FALSE(
        kasumi::valid_snapshot(Snapshot{{make_directory(""),
                                         make_file("duplicate", "first", 5),
                                         make_file("duplicate", "second", 6)}},
                               false));
    EXPECT_FALSE(kasumi::valid_snapshot(
        Snapshot{
            {make_directory(""), make_directory("b"), make_directory("a")}},
        false));
    EXPECT_FALSE(kasumi::valid_snapshot(
        Snapshot{{make_directory(""), make_file("/absolute", "", 0)}}, false));
    EXPECT_FALSE(kasumi::valid_snapshot(
        Snapshot{{make_directory(""), make_file("../escape", "", 0)}}, false));
    EXPECT_FALSE(kasumi::valid_snapshot(
        Snapshot{{make_directory(""), make_file("folder/file.txt", "", 0)}},
        false));
}

TEST(SnapshotTest, ExposesConstAndMutableLookupWithoutMatchingPrefixes) {
    Snapshot snapshot{{
        make_file("notes/today.txt", "today", 5),
        make_directory(""),
        make_file("notes-archive.txt", "archive", 7),
        make_directory("notes"),
    }};
    kasumi::finalize_snapshot(snapshot);

    const Snapshot& immutable = snapshot;
    const NodeRow* const_row = kasumi::find_row(immutable, "notes/today.txt");
    ASSERT_NE(const_row, nullptr);
    EXPECT_EQ(const_row->size, std::uint64_t{5});
    EXPECT_EQ(kasumi::find_row(immutable, "notes/today"), nullptr);
    EXPECT_EQ(kasumi::find_row(immutable, "notes-archive"), nullptr);

    NodeRow* mutable_row = kasumi::find_row(snapshot, "notes/today.txt");
    ASSERT_NE(mutable_row, nullptr);
    mutable_row->size = 19;
    EXPECT_EQ(mutable_row->size, std::uint64_t{19});
}

TEST(SnapshotTest, SortsRowsAndKeepsEachSubtreeContiguous) {
    Snapshot snapshot{{
        make_file("project-old/readme.txt", "old", 3),
        make_file("project/src/main.cpp", "main", 4),
        make_directory("project-old"),
        make_directory(""),
        make_file("project/tests/case.cpp", "case", 4),
        make_directory("project/tests"),
        make_directory("project"),
        make_directory("project/src"),
    }};

    kasumi::finalize_snapshot(snapshot);

    EXPECT_EQ(paths_of(snapshot),
              (std::vector<std::string>{
                  "",
                  "project",
                  "project/src",
                  "project/src/main.cpp",
                  "project/tests",
                  "project/tests/case.cpp",
                  "project-old",
                  "project-old/readme.txt",
              }));
    const NodeRow* root = kasumi::find_row(snapshot, "");
    ASSERT_NE(root, nullptr);
    const Hash first_root_hash = root->hash;
    kasumi::finalize_snapshot(snapshot);
    root = kasumi::find_row(snapshot, "");
    ASSERT_NE(root, nullptr);
    EXPECT_EQ(root->hash, first_root_hash);
}

TEST(SnapshotTest, ChangingADeepChildChangesEveryAncestorHash) {
    Snapshot snapshot{{
        make_directory(""),
        make_directory("docs"),
        make_directory("docs/guides"),
        make_file("docs/guides/start.txt", "first revision", 14),
    }};
    kasumi::finalize_snapshot(snapshot);

    const NodeRow* root = kasumi::find_row(snapshot, "");
    const NodeRow* docs = kasumi::find_row(snapshot, "docs");
    const NodeRow* guides = kasumi::find_row(snapshot, "docs/guides");
    ASSERT_NE(root, nullptr);
    ASSERT_NE(docs, nullptr);
    ASSERT_NE(guides, nullptr);
    const Hash root_before = root->hash;
    const Hash docs_before = docs->hash;
    const Hash guides_before = guides->hash;

    NodeRow* child = kasumi::find_row(snapshot, "docs/guides/start.txt");
    ASSERT_NE(child, nullptr);
    child->hash = kasumi::hasher::hash_string("second revision");
    kasumi::finalize_snapshot(snapshot);

    root = kasumi::find_row(snapshot, "");
    docs = kasumi::find_row(snapshot, "docs");
    guides = kasumi::find_row(snapshot, "docs/guides");
    ASSERT_NE(root, nullptr);
    ASSERT_NE(docs, nullptr);
    ASSERT_NE(guides, nullptr);
    EXPECT_NE(guides->hash, guides_before);
    EXPECT_NE(docs->hash, docs_before);
    EXPECT_NE(root->hash, root_before);
}

TEST(SnapshotTest, EquivalentInsertionOrdersProduceTheSameCanonicalSnapshot) {
    const auto root_time =
        std::filesystem::file_time_type{} + std::chrono::seconds{10};
    const auto directory_time =
        std::filesystem::file_time_type{} + std::chrono::seconds{20};
    const auto file_time =
        std::filesystem::file_time_type{} + std::chrono::seconds{30};

    std::vector<NodeRow> rows{
        make_directory("", root_time),
        make_directory("media", directory_time),
        make_file("media/song.bin", "audio-bytes", 11, file_time),
        make_directory("unused", directory_time),
    };
    Snapshot forward{rows};
    std::ranges::reverse(rows);
    Snapshot reverse{std::move(rows)};

    kasumi::finalize_snapshot(forward);
    kasumi::finalize_snapshot(reverse);

    ASSERT_EQ(forward.rows.size(), reverse.rows.size());
    for (std::size_t index = 0; index < forward.rows.size(); ++index) {
        const auto& left = forward.rows[index];
        const auto& right = reverse.rows[index];
        EXPECT_EQ(left.path, right.path);
        EXPECT_EQ(left.hash, right.hash);
        EXPECT_EQ(left.size, right.size);
        EXPECT_EQ(left.mtime, right.mtime);
        EXPECT_EQ(left.is_directory, right.is_directory);
    }
}

TEST(SnapshotTest, FinalizesRootOnlyAndEmptyDirectoriesDeterministically) {
    Snapshot root_only{{make_directory("")}};
    kasumi::finalize_snapshot(root_only);

    ASSERT_EQ(root_only.rows.size(), 1U);
    EXPECT_EQ(root_only.rows.front().hash, kasumi::hasher::hash_string(""));
    EXPECT_EQ(root_only.rows.front().size, std::uint64_t{0});

    Snapshot with_empty_directory{{
        make_directory("cache"),
        make_directory(""),
    }};
    kasumi::finalize_snapshot(with_empty_directory);

    const NodeRow* empty_directory =
        kasumi::find_row(with_empty_directory, "cache");
    ASSERT_NE(empty_directory, nullptr);
    EXPECT_TRUE(empty_directory->is_directory);
    EXPECT_EQ(empty_directory->hash, kasumi::hasher::hash_string(""));
    EXPECT_EQ(empty_directory->size, std::uint64_t{0});

    const NodeRow* root = kasumi::find_row(with_empty_directory, "");
    ASSERT_NE(root, nullptr);
    const Hash root_hash = root->hash;
    kasumi::finalize_snapshot(with_empty_directory);
    root = kasumi::find_row(with_empty_directory, "");
    ASSERT_NE(root, nullptr);
    EXPECT_EQ(root->hash, root_hash);
}

TEST(SnapshotTest, PreservesFileMetadataAndDerivesDirectoryMetadata) {
    const auto root_time =
        std::filesystem::file_time_type{} + std::chrono::seconds{101};
    const auto assets_time =
        std::filesystem::file_time_type{} + std::chrono::seconds{202};
    const auto images_time =
        std::filesystem::file_time_type{} + std::chrono::seconds{303};
    const auto file_time =
        std::filesystem::file_time_type{} + std::chrono::seconds{404};
    const Hash placeholder_hash =
        kasumi::hasher::hash_string("directory placeholder");
    const Hash logo_hash = kasumi::hasher::hash_string("logo contents");

    NodeRow root = make_directory("", root_time);
    NodeRow assets = make_directory("assets", assets_time);
    assets.hash = placeholder_hash;
    assets.size = 999;
    NodeRow images = make_directory("assets/images", images_time);
    images.hash = placeholder_hash;
    images.size = 888;
    NodeRow logo =
        make_file("assets/images/logo.bin", "logo contents", 29, file_time);
    NodeRow license = make_file("assets/license.txt", "license", 13, file_time);

    Snapshot snapshot{{
        std::move(logo),
        std::move(assets),
        std::move(root),
        std::move(license),
        std::move(images),
    }};
    kasumi::finalize_snapshot(snapshot);

    const NodeRow* finalized_logo =
        kasumi::find_row(snapshot, "assets/images/logo.bin");
    const NodeRow* finalized_images =
        kasumi::find_row(snapshot, "assets/images");
    const NodeRow* finalized_assets = kasumi::find_row(snapshot, "assets");
    const NodeRow* finalized_root = kasumi::find_row(snapshot, "");
    ASSERT_NE(finalized_logo, nullptr);
    ASSERT_NE(finalized_images, nullptr);
    ASSERT_NE(finalized_assets, nullptr);
    ASSERT_NE(finalized_root, nullptr);

    EXPECT_FALSE(finalized_logo->is_directory);
    EXPECT_EQ(finalized_logo->hash, logo_hash);
    EXPECT_EQ(finalized_logo->size, std::uint64_t{29});
    EXPECT_EQ(finalized_logo->mtime, file_time);

    EXPECT_TRUE(finalized_images->is_directory);
    EXPECT_TRUE(finalized_assets->is_directory);
    EXPECT_TRUE(finalized_root->is_directory);
    EXPECT_EQ(finalized_images->mtime, images_time);
    EXPECT_EQ(finalized_assets->mtime, assets_time);
    EXPECT_EQ(finalized_root->mtime, root_time);
    EXPECT_EQ(finalized_images->size, std::uint64_t{29});
    EXPECT_EQ(finalized_assets->size, std::uint64_t{42});
    EXPECT_EQ(finalized_root->size, std::uint64_t{42});
    EXPECT_NE(finalized_images->hash, placeholder_hash);
    EXPECT_NE(finalized_assets->hash, placeholder_hash);
}

TEST(PortableComponentTest, ValidatesPortableNames) {
    // Valid components
    EXPECT_TRUE(kasumi::valid_logical_path_component("file.txt"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("Folder Name"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("résumé.txt"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("日本.txt"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("emoji-☁.txt"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("usuário-日本-☁.txt"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("a-b_c.123"));
    EXPECT_TRUE(kasumi::valid_logical_path_component(" leading_space"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("contact.txt"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("auxiliary"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("CON1"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("COM0"));
    EXPECT_TRUE(kasumi::valid_logical_path_component("LPT0"));
    EXPECT_TRUE(kasumi::valid_logical_path_component(std::string(255, 'a')));

    // Empty and relative dot entries
    EXPECT_FALSE(kasumi::valid_logical_path_component(""));
    EXPECT_FALSE(kasumi::valid_logical_path_component("."));
    EXPECT_FALSE(kasumi::valid_logical_path_component(".."));

    // Length limit > 255 bytes
    EXPECT_FALSE(kasumi::valid_logical_path_component(std::string(256, 'a')));

    // Forbidden ASCII characters
    EXPECT_FALSE(kasumi::valid_logical_path_component("a\\b"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("a:b"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("a<b"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("a>b"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("a\"b"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("a|b"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("a?b"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("a*b"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("a/b"));

    // Trailing dot or space
    EXPECT_FALSE(kasumi::valid_logical_path_component("file."));
    EXPECT_FALSE(kasumi::valid_logical_path_component("file "));
    EXPECT_FALSE(kasumi::valid_logical_path_component(" "));
    EXPECT_FALSE(kasumi::valid_logical_path_component("..."));

    // Reserved DOS device names
    EXPECT_FALSE(kasumi::valid_logical_path_component("CON"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("con"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("CON.txt"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("nul.bin"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("COM1"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("com9.log"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("LPT1"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("lpt9.foo"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("AUX"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("PRN"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("COM\xC2\xB9"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("COM\xC2\xB9.log"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("LPT\xC2\xB3"));

    // Control characters and DEL
    EXPECT_FALSE(kasumi::valid_logical_path_component(std::string("a\x01"
                                                                  "b",
                                                                  3)));
    EXPECT_FALSE(kasumi::valid_logical_path_component(std::string("a\x1F"
                                                                  "b",
                                                                  3)));
    EXPECT_FALSE(kasumi::valid_logical_path_component(std::string("a\x7F"
                                                                  "b",
                                                                  3)));
    EXPECT_FALSE(kasumi::valid_logical_path_component(std::string("a\x00"
                                                                  "b",
                                                                  3)));

    // Structural invalid UTF-8
    EXPECT_FALSE(kasumi::valid_logical_path_component("\xC2"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("\xC0\xAF"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("\xE0\x80\xAF"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("\xED\xA0\x80"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("\xF0\x80\x80\xAF"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("\xF4\x90\x80\x80"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("\x80"));
    EXPECT_FALSE(kasumi::valid_logical_path_component("\xFF"));
}

TEST(SnapshotValidationTest, RejectsNonPortableLogicalComponents) {
    // Valid snapshot with Unicode and portable names
    Snapshot valid_tree{{
        make_directory(""),
        make_directory("Folder Name"),
        make_file("Folder Name/résumé.txt", "resume", 6),
        make_file("emoji-☁.txt", "cloud", 5),
        make_file("file.txt", "text", 4),
        make_file("日本.txt", "nihon", 5),
    }};
    kasumi::finalize_snapshot(valid_tree);
    EXPECT_TRUE(kasumi::valid_snapshot(valid_tree, false));

    // Valid nested hierarchy
    Snapshot valid_nested{{
        make_directory(""),
        make_directory("a"),
        make_directory("a/b"),
        make_file("a/b/c.txt", "c", 1),
    }};
    kasumi::finalize_snapshot(valid_nested);
    EXPECT_TRUE(kasumi::valid_snapshot(valid_nested, false));

    // Non-portable: backslash in component
    Snapshot bad_backslash{{
        make_directory(""),
        make_file("a\\b", "bad", 3),
    }};
    kasumi::finalize_snapshot(bad_backslash);
    EXPECT_FALSE(kasumi::valid_snapshot(bad_backslash, false));

    // Non-portable: colon in component
    Snapshot bad_colon{{
        make_directory(""),
        make_file("a:b", "bad", 3),
    }};
    kasumi::finalize_snapshot(bad_colon);
    EXPECT_FALSE(kasumi::valid_snapshot(bad_colon, false));

    // Non-portable: reserved DOS device
    Snapshot bad_device{{
        make_directory(""),
        make_file("CON.txt", "bad", 3),
    }};
    kasumi::finalize_snapshot(bad_device);
    EXPECT_FALSE(kasumi::valid_snapshot(bad_device, false));

    // Non-portable: trailing dot
    Snapshot bad_dot{{
        make_directory(""),
        make_file("file.", "bad", 3),
    }};
    kasumi::finalize_snapshot(bad_dot);
    EXPECT_FALSE(kasumi::valid_snapshot(bad_dot, false));

    // Non-portable: trailing space
    Snapshot bad_space{{
        make_directory(""),
        make_file("file ", "bad", 3),
    }};
    kasumi::finalize_snapshot(bad_space);
    EXPECT_FALSE(kasumi::valid_snapshot(bad_space, false));

    // Non-portable: oversized component (> 255 bytes)
    Snapshot bad_oversized{{
        make_directory(""),
        make_file(std::string(256, 'x'), "bad", 3),
    }};
    kasumi::finalize_snapshot(bad_oversized);
    EXPECT_FALSE(kasumi::valid_snapshot(bad_oversized, false));

    // Unicode case collision: Ä vs ä
    Snapshot bad_auml{{
        make_directory(""),
        make_file("Ä.txt", "upper", 5),
        make_file("ä.txt", "lower", 5),
    }};
    kasumi::finalize_snapshot(bad_auml);
    EXPECT_FALSE(kasumi::valid_snapshot(bad_auml, false));

    // Unicode case collision: Ω vs ω
    Snapshot bad_omega{{
        make_directory(""),
        make_file("Ω.txt", "upper", 5),
        make_file("ω.txt", "lower", 5),
    }};
    kasumi::finalize_snapshot(bad_omega);
    EXPECT_FALSE(kasumi::valid_snapshot(bad_omega, false));

    // Unicode case collision in directory hierarchy: Ä/file.txt vs ä/file.txt
    Snapshot bad_dir_unicode{{
        make_directory(""),
        make_directory("Ä"),
        make_file("Ä/file.txt", "upper", 5),
        make_directory("ä"),
        make_file("ä/file.txt", "lower", 5),
    }};
    kasumi::finalize_snapshot(bad_dir_unicode);
    EXPECT_FALSE(kasumi::valid_snapshot(bad_dir_unicode, false));
}

TEST(SnapshotValidationTest, RejectsAsciiCaseCollisions) {
    // foo + FOO -> invalid
    Snapshot tree_foo{{
        make_directory(""),
        make_file("FOO", "upper", 5),
        make_file("foo", "lower", 5),
    }};
    kasumi::finalize_snapshot(tree_foo);
    EXPECT_FALSE(kasumi::valid_snapshot(tree_foo, false));

    // Readme + README -> invalid
    Snapshot tree_readme{{
        make_directory(""),
        make_file("README", "upper", 5),
        make_file("Readme", "mixed", 5),
    }};
    kasumi::finalize_snapshot(tree_readme);
    EXPECT_FALSE(kasumi::valid_snapshot(tree_readme, false));

    // dir/a + dir/A -> invalid
    Snapshot tree_dir{{
        make_directory(""),
        make_directory("dir"),
        make_file("dir/A", "upper", 1),
        make_file("dir/a", "lower", 1),
    }};
    kasumi::finalize_snapshot(tree_dir);
    EXPECT_FALSE(kasumi::valid_snapshot(tree_dir, false));

    // a/foo + b/FOO -> valid (different parents)
    Snapshot tree_diff_parents{{
        make_directory(""),
        make_directory("a"),
        make_file("a/foo", "a_foo", 5),
        make_directory("b"),
        make_file("b/FOO", "b_foo", 5),
    }};
    kasumi::finalize_snapshot(tree_diff_parents);
    EXPECT_TRUE(kasumi::valid_snapshot(tree_diff_parents, false));

    // foo and FooBar -> valid (no prefix false positive)
    Snapshot tree_prefix{{
        make_directory(""),
        make_file("FooBar", "bar", 3),
        make_file("foo", "foo", 3),
    }};
    kasumi::finalize_snapshot(tree_prefix);
    EXPECT_TRUE(kasumi::valid_snapshot(tree_prefix, false));

    // Latin: É vs é
    Snapshot tree_eacu{{
        make_directory(""),
        make_file("É.txt", "upper", 5),
        make_file("é.txt", "lower", 5),
    }};
    kasumi::finalize_snapshot(tree_eacu);
    EXPECT_FALSE(kasumi::valid_snapshot(tree_eacu, false));

    // Latin: Ö vs ö
    Snapshot tree_ouml{{
        make_directory(""),
        make_file("Ö.txt", "upper", 5),
        make_file("ö.txt", "lower", 5),
    }};
    kasumi::finalize_snapshot(tree_ouml);
    EXPECT_FALSE(kasumi::valid_snapshot(tree_ouml, false));

    // Cyrillic: Я vs я
    Snapshot tree_ya{{
        make_directory(""),
        make_file("Я.txt", "upper", 5),
        make_file("я.txt", "lower", 5),
    }};
    kasumi::finalize_snapshot(tree_ya);
    EXPECT_FALSE(kasumi::valid_snapshot(tree_ya, false));

    // Non-equivalence: 日本.txt vs 日本2.txt -> valid
    Snapshot tree_japan{{
        make_directory(""),
        make_file("日本.txt", "japan1", 6),
        make_file("日本2.txt", "japan2", 7),
    }};
    kasumi::finalize_snapshot(tree_japan);
    EXPECT_TRUE(kasumi::valid_snapshot(tree_japan, false));

    // a/Ä.txt + b/ä.txt -> valid (different parents)
    Snapshot tree_diff_parents_unicode{{
        make_directory(""),
        make_directory("a"),
        make_file("a/Ä.txt", "a_upper", 5),
        make_directory("b"),
        make_file("b/ä.txt", "b_lower", 5),
    }};
    kasumi::finalize_snapshot(tree_diff_parents_unicode);
    EXPECT_TRUE(kasumi::valid_snapshot(tree_diff_parents_unicode, false));
}

TEST(PortableCaseKeyTest, EquivalenceAndDistinct) {
    EXPECT_EQ(kasumi::unicode_version(), "17.0.0");

    // ASCII
    EXPECT_EQ(kasumi::portable_case_key("FILE.txt"),
              kasumi::portable_case_key("file.txt"));
    EXPECT_EQ(kasumi::portable_case_key("Foo/Bar"),
              kasumi::portable_case_key("foo/bar"));

    // Latin
    EXPECT_EQ(kasumi::portable_case_key("Ä.txt"),
              kasumi::portable_case_key("ä.txt"));
    EXPECT_EQ(kasumi::portable_case_key("É.txt"),
              kasumi::portable_case_key("é.txt"));
    EXPECT_EQ(kasumi::portable_case_key("Ö.txt"),
              kasumi::portable_case_key("ö.txt"));

    // Greek
    EXPECT_EQ(kasumi::portable_case_key("Ω.txt"),
              kasumi::portable_case_key("ω.txt"));

    // Cyrillic
    EXPECT_EQ(kasumi::portable_case_key("Я.txt"),
              kasumi::portable_case_key("я.txt"));

    // Caseless / distinct
    EXPECT_NE(kasumi::portable_case_key("日本.txt"),
              kasumi::portable_case_key("日本2.txt"));
    EXPECT_NE(kasumi::portable_case_key("☁.txt"),
              kasumi::portable_case_key("☀.txt"));

    // Preserve separators
    EXPECT_EQ(kasumi::portable_case_key("Ä/Ω.txt"),
              kasumi::portable_case_key("ä/ω.txt"));
    EXPECT_NE(kasumi::portable_case_key("Ä/Ω.txt"),
              kasumi::portable_case_key("Ä_Ω.txt"));
}

TEST(ConflictPathTest, HandlesBoundedTruncationAndDeviceNames) {
    // Local and remote suffixes
    const auto remote_conflict =
        kasumi::make_conflict_path("doc.txt", ".kasumiconflict_remote");
    EXPECT_EQ(remote_conflict, "doc.txt.kasumiconflict_remote");
    EXPECT_TRUE(kasumi::valid_logical_path_component(remote_conflict));

    const auto local_conflict =
        kasumi::make_conflict_path("nested/doc.txt", ".kasumiconflict_local");
    EXPECT_EQ(local_conflict, "nested/doc.txt.kasumiconflict_local");
    EXPECT_TRUE(
        kasumi::valid_logical_path_component(kasumi::row_name(local_conflict)));

    // Numbered suffix
    const auto numbered_conflict =
        kasumi::make_conflict_path("doc.txt.kasumiconflict_remote", ".1");
    EXPECT_EQ(numbered_conflict, "doc.txt.kasumiconflict_remote.1");

    // Close to 255-byte limit
    const std::string long_name(245, 'a');
    const auto bounded =
        kasumi::make_conflict_path(long_name, ".kasumiconflict_remote");
    EXPECT_LE(bounded.size(), 255U);
    EXPECT_TRUE(bounded.ends_with(".kasumiconflict_remote"));
    EXPECT_TRUE(kasumi::valid_logical_path_component(bounded));

    // UTF-8 truncation boundary (never split multi-byte sequence)
    // 231 ASCII 'x' + "日本" (6 bytes) = 237 bytes. Suffix is 23 bytes
    // (.kasumiconflict_remote). Available space: 255 - 23 = 232 bytes. 231
    // bytes + 1st byte of "日" would split the code point. Truncation must stop
    // before "日", leaving exactly 231 'x' chars.
    std::string utf8_name(231, 'x');
    utf8_name += "日本";
    const auto truncated_utf8 =
        kasumi::make_conflict_path(utf8_name, ".kasumiconflict_remote");
    EXPECT_LE(truncated_utf8.size(), 255U);
    EXPECT_TRUE(truncated_utf8.ends_with(".kasumiconflict_remote"));
    EXPECT_TRUE(kasumi::valid_logical_path_component(truncated_utf8));
    EXPECT_EQ(truncated_utf8.substr(0, 231), std::string(231, 'x'));

    // DOS device adjustment
    const auto dos_conflict =
        kasumi::make_conflict_path("CON.txt", ".kasumiconflict_remote");
    EXPECT_EQ(dos_conflict, "_CON.txt.kasumiconflict_remote");
    EXPECT_TRUE(kasumi::valid_logical_path_component(dos_conflict));

    const auto dos_bare_conflict =
        kasumi::make_conflict_path("aux", ".kasumiconflict_local");
    EXPECT_EQ(dos_bare_conflict, "_aux.kasumiconflict_local");
    EXPECT_TRUE(kasumi::valid_logical_path_component(dos_bare_conflict));
}

} // namespace
