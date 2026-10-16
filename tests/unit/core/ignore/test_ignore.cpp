#include "core/ignore.hpp"

#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::ignore {
namespace {

TEST(IgnoreTest, ReservedInternalFilesRemainExcluded) {
    const IgnoreList empty_list{};
    for (const auto path : {"kasumi.db",
                            "kasumi.db-shm",
                            "kasumi.db-wal",
                            "kasumi.lock",
                            ".kasumi_sync_buffer"}) {
        EXPECT_TRUE(is_reserved_internal(path));
        EXPECT_TRUE(is_ignored(path, empty_list, false));
    }
}

TEST(IgnoreTest, OnlyGeneratedKasumiArtifactsAreReserved) {
    constexpr auto id = "0123456789abcdef0123456789abcdef";
    EXPECT_TRUE(is_reserved_internal(
        std::string("docs/file.txt.kasumi-custody-") + id + "-0"));
    EXPECT_TRUE(is_reserved_internal(
        std::string("nested\\file.txt.kasumi-rollback-candidate-") + id +
        "-12"));
    EXPECT_TRUE(
        is_reserved_internal(std::string("file.kasumi-new-") + id + "-3"));

    EXPECT_FALSE(is_reserved_internal(".kasumi-notes.md"));
    EXPECT_FALSE(is_reserved_internal("my.kasumi-rollback-guide.txt"));
    EXPECT_FALSE(
        is_reserved_internal(std::string("file.kasumi-custody-") + id + "-x"));
    EXPECT_FALSE(
        is_reserved_internal("file.kasumi-custody-0123456789abcdef-0"));
    EXPECT_FALSE(
        is_reserved_internal("file.kasumi-unknown-" + std::string(id) + "-0"));
}

TEST(IgnoreTest, EmptyIgnoreListMatchesNothing) {
    const IgnoreList empty_list{};
    EXPECT_FALSE(is_ignored("file.txt", empty_list, false));
    EXPECT_FALSE(is_ignored("dir/file.txt", empty_list, false));
    EXPECT_FALSE(is_ignored("some_dir", empty_list, true));
}

TEST(IgnoreTest, LiteralBasenameMatchesAnyDepth) {
    const auto list = parse_ignore_rules("Thumbs.db\ndesktop.ini\n");
    EXPECT_TRUE(is_ignored("Thumbs.db", list, false));
    EXPECT_TRUE(is_ignored("subdir/Thumbs.db", list, false));
    EXPECT_TRUE(is_ignored("a/b/c/Thumbs.db", list, false));
    EXPECT_TRUE(is_ignored("desktop.ini", list, false));
    EXPECT_TRUE(is_ignored("folder/desktop.ini", list, false));

    // Substrings do not match
    EXPECT_FALSE(is_ignored("Thumbs.db.txt", list, false));
    EXPECT_FALSE(is_ignored("MyThumbs.db", list, false));
    EXPECT_FALSE(is_ignored("desktop.ini.bak", list, false));
}

TEST(IgnoreTest, ExtensionPatternMatchesAnyDepth) {
    const auto list = parse_ignore_rules("*.log\n*.tmp\n");
    EXPECT_TRUE(is_ignored("error.log", list, false));
    EXPECT_TRUE(is_ignored("var/log/app.log", list, false));
    EXPECT_TRUE(is_ignored("a/b/c/debug.tmp", list, false));

    EXPECT_FALSE(is_ignored("log", list, false));
    EXPECT_FALSE(is_ignored("logger.txt", list, false));
    EXPECT_FALSE(is_ignored("app.log.bak", list, false));
    EXPECT_FALSE(is_ignored("tmp", list, false));
}

TEST(IgnoreTest, DirectoryOnlyRuleDifferentiatesFilesAndDirectories) {
    const auto list = parse_ignore_rules("node_modules/\ntarget/\n");

    // Match directories
    EXPECT_TRUE(is_ignored("node_modules", list, true));
    EXPECT_TRUE(is_ignored("src/node_modules", list, true));
    EXPECT_TRUE(is_ignored("target", list, true));

    // Do NOT match files with same name
    EXPECT_FALSE(is_ignored("node_modules", list, false));
    EXPECT_FALSE(is_ignored("src/node_modules", list, false));
    EXPECT_FALSE(is_ignored("target", list, false));

    // Ancestor directory matching: files inside ignored directories are ignored
    EXPECT_TRUE(is_ignored("node_modules/package.json", list, false));
    EXPECT_TRUE(is_ignored("src/node_modules/lib.js", list, false));
    EXPECT_TRUE(is_ignored("target/debug/build.o", list, false));
}

TEST(IgnoreTest, AnchoredRuleMatchesOnlyAtRoot) {
    const auto list = parse_ignore_rules("/build/\n/app.exe\n");

    // Root matches
    EXPECT_TRUE(is_ignored("build", list, true));
    EXPECT_TRUE(is_ignored("build/main.o", list, false));
    EXPECT_TRUE(is_ignored("app.exe", list, false));

    // Nested does NOT match
    EXPECT_FALSE(is_ignored("src/build", list, true));
    EXPECT_FALSE(is_ignored("src/build/main.o", list, false));
    EXPECT_FALSE(is_ignored("bin/app.exe", list, false));
}

TEST(IgnoreTest, InternalSlashRuleMatchesPrefixFromRoot) {
    const auto list = parse_ignore_rules("Win32/Debug/\napp/build/\n");

    EXPECT_TRUE(is_ignored("Win32/Debug", list, true));
    EXPECT_TRUE(is_ignored("Win32/Debug/output.exe", list, false));
    EXPECT_TRUE(is_ignored("app/build", list, true));
    EXPECT_TRUE(is_ignored("app/build/app.apk", list, false));

    // Does not match when not at prefix
    EXPECT_FALSE(is_ignored("other/Win32/Debug", list, true));
    EXPECT_FALSE(is_ignored("other/Win32/Debug/output.exe", list, false));
}

TEST(IgnoreTest, NegationAndRuleOrderPrecedence) {
    const auto list = parse_ignore_rules("*.log\n!important.log\n");
    EXPECT_TRUE(is_ignored("error.log", list, false));
    EXPECT_TRUE(is_ignored("debug.log", list, false));
    EXPECT_FALSE(is_ignored("important.log", list, false));
    EXPECT_FALSE(is_ignored("subdir/important.log", list, false));

    // Order matters: later rule overrides earlier rule
    const auto re_ignored =
        parse_ignore_rules("*.log\n!important.log\nimportant.log\n");
    EXPECT_TRUE(is_ignored("important.log", re_ignored, false));

    // Negation inside ignored directory
    const auto dir_neg = parse_ignore_rules("build/\n!build/keep.txt\n");
    EXPECT_TRUE(is_ignored("build", dir_neg, true));
    EXPECT_TRUE(is_ignored("build/trash.o", dir_neg, false));
    EXPECT_FALSE(is_ignored("build/keep.txt", dir_neg, false));
}

TEST(IgnoreTest, GlobPatternsQuestionMarkAndStar) {
    const auto list = parse_ignore_rules("doc?.txt\nfoo*bar\n");

    EXPECT_TRUE(is_ignored("doc1.txt", list, false));
    EXPECT_TRUE(is_ignored("docA.txt", list, false));
    EXPECT_FALSE(is_ignored("doc.txt", list, false));
    EXPECT_FALSE(is_ignored("doc12.txt", list, false));
    EXPECT_FALSE(is_ignored("doc/.txt", list, false));

    EXPECT_TRUE(is_ignored("foobar", list, false));
    EXPECT_TRUE(is_ignored("foo123bar", list, false));
    EXPECT_FALSE(
        is_ignored("foo/bar", list, false)); // single * does not cross /
}

TEST(IgnoreTest, GlobDoubleStarMatchesAcrossSlashes) {
    const auto list = parse_ignore_rules("a/**/b\n");

    EXPECT_TRUE(is_ignored("a/b", list, false));
    EXPECT_TRUE(is_ignored("a/x/b", list, false));
    EXPECT_TRUE(is_ignored("a/x/y/b", list, false));
    EXPECT_FALSE(is_ignored(
        "other/a/b", list, false)); // contains slash, anchored at start
}

TEST(IgnoreTest, UnicodeAndSpecialCharacters) {
    const auto list =
        parse_ignore_rules("/Gravações de som/\n*.тест\nRelatório.docx\n");

    EXPECT_TRUE(is_ignored("Gravações de som", list, true));
    EXPECT_TRUE(is_ignored("Gravações de som/áudio.wav", list, false));
    EXPECT_FALSE(is_ignored("sub/Gravações de som", list, true));

    EXPECT_TRUE(is_ignored("документ.тест", list, false));
    EXPECT_TRUE(is_ignored("sub/документ.тест", list, false));

    EXPECT_TRUE(is_ignored("Relatório.docx", list, false));
    EXPECT_TRUE(is_ignored("pasta/Relatório.docx", list, false));
    EXPECT_FALSE(is_ignored("BanG Dream!.md", list, false));
}

TEST(IgnoreTest, ParsingBOMCommentsEscapingAndWhitespace) {
    std::string content = "\xEF\xBB\xBF# Comment at top with BOM\r\n"
                          "*.bak\r\n"
                          "\\#literal_hash.txt\r\n"
                          "\\!literal_exclamation.txt\r\n"
                          "trailing_spaces.txt   \r\n"
                          "escaped_space.txt\\ \r\n";

    const auto list = parse_ignore_rules(content);
    EXPECT_TRUE(is_ignored("file.bak", list, false));
    EXPECT_TRUE(is_ignored("#literal_hash.txt", list, false));
    EXPECT_TRUE(is_ignored("!literal_exclamation.txt", list, false));
    EXPECT_TRUE(is_ignored("trailing_spaces.txt", list, false));
    EXPECT_TRUE(is_ignored("escaped_space.txt ", list, false));
}

TEST(IgnoreTest, PatternSizeLimitSkipped) {
    std::string long_pattern(300, 'x');
    long_pattern += "\nvalid.txt\n";
    const auto list = parse_ignore_rules(long_pattern);

    EXPECT_EQ(list.rules.size(), 1u);
    EXPECT_TRUE(is_ignored("valid.txt", list, false));
}

TEST(IgnoreTest, AnchoredWildcardDoesNotMatchSubdirectories) {
    // Specifically test anchored extension: /*.txt only matches root .txt files
    const auto list_txt = parse_ignore_rules("/*.txt\n");
    EXPECT_TRUE(is_ignored("file.txt", list_txt, false));
    EXPECT_FALSE(is_ignored("a/file.txt", list_txt, false));
    EXPECT_FALSE(is_ignored("a/b/file.txt", list_txt, false));

    // Multi-rule anchored wildcard set
    // Note: root directory 'sub' has length > 1 so it is not matched by /?
    const auto list = parse_ignore_rules("/*.txt\n/*.a\n/*foo*\n/?\n");

    // Root matches
    EXPECT_TRUE(is_ignored("file.txt", list, false));
    EXPECT_TRUE(is_ignored("lib.a", list, false));
    EXPECT_TRUE(is_ignored("foobar", list, false));
    EXPECT_TRUE(is_ignored("myfoobaz", list, false));
    EXPECT_TRUE(is_ignored("x", list, false));

    // Subdirectories must NOT match (single * and ? cannot cross /)
    EXPECT_FALSE(is_ignored("sub/b/file.txt", list, false));
    EXPECT_FALSE(is_ignored("include/lib/file.a", list, false));
    EXPECT_FALSE(is_ignored("dir/foobar", list, false));
    EXPECT_FALSE(is_ignored("sub/b/c/foobar", list, false));
    EXPECT_FALSE(is_ignored("dir/x", list, false));
}

TEST(IgnoreTest, AnchoredLiteralAndDirectoryRules) {
    const auto list = parse_ignore_rules("/file.txt\n/build/\n");

    EXPECT_TRUE(is_ignored("file.txt", list, false));
    EXPECT_FALSE(is_ignored("a/file.txt", list, false));
    EXPECT_FALSE(is_ignored("a/b/file.txt", list, false));

    EXPECT_TRUE(is_ignored("build", list, true));
    EXPECT_TRUE(is_ignored("build/out.o", list, false));
    EXPECT_FALSE(is_ignored("a/build", list, true));
    EXPECT_FALSE(is_ignored("a/build/out.o", list, false));
}

TEST(IgnoreTest, AnchoredDoubleStarMatchesAcrossSubdirectories) {
    const auto list = parse_ignore_rules("/**/bar\n/**.log\n");

    EXPECT_TRUE(is_ignored("bar", list, false));
    EXPECT_TRUE(is_ignored("a/bar", list, false));
    EXPECT_TRUE(is_ignored("a/b/c/bar", list, false));

    EXPECT_TRUE(is_ignored("test.log", list, false));
    EXPECT_TRUE(is_ignored("a/b/test.log", list, false));
}

TEST(IgnoreTest, DeepPathsBeyondStackBufferThreshold) {
    const auto list = parse_ignore_rules("*.target\nmarker\n/deep/root.txt\n");

    // Depth 40 (exceeds stack buffer of 32, triggering heap fallback)
    std::string path_deep = "";
    for (int i = 0; i < 40; ++i) {
        path_deep += "level" + std::to_string(i) + "/";
    }

    EXPECT_TRUE(is_ignored(path_deep + "file.target", list, false));
    EXPECT_TRUE(is_ignored(path_deep + "marker", list, false));
    EXPECT_FALSE(is_ignored(path_deep + "normal.txt", list, false));
    EXPECT_FALSE(is_ignored(path_deep + "deep/root.txt", list, false));
}

} // namespace
} // namespace kasumi::ignore
