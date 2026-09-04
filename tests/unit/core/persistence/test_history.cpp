#include "core/history.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace kasumi::history;

namespace {

std::filesystem::file_time_type canonical_time(std::int64_t nanos) {
    using FileDuration = std::filesystem::file_time_type::duration;
    const auto delta = std::chrono::duration_cast<FileDuration>(
        std::chrono::nanoseconds{nanos});
    const auto origin = std::chrono::clock_cast<std::chrono::file_clock>(
                            std::chrono::system_clock::time_point{})
                            .time_since_epoch();
    return std::filesystem::file_time_type{
        FileDuration{origin.count() + delta.count()}};
}

kasumi::Snapshot make_custom_snapshot(int i) {
    kasumi::Snapshot tree{
        .rows =
            {
                kasumi::NodeRow{
                    .path = "",
                    .hash = {},
                    .size = 0,
                    .mtime = canonical_time(static_cast<std::int64_t>(i) * 1'000'000),
                    .is_directory = true,
                },
            },
    };
    kasumi::finalize_snapshot(tree);
    return tree;
}

kasumi::Snapshot make_valid_snapshot() {
    return make_custom_snapshot(0);
}

kasumi::Snapshot make_empty_snapshot() {
    kasumi::Snapshot tree;
    return tree;
}

kasumi::NodeRow
make_file(std::string path, std::string content, std::int64_t mtime = 0) {
    return kasumi::NodeRow{
        .path = std::move(path),
        .hash = kasumi::hasher::hash_string(content),
        .size = content.size(),
        .mtime = canonical_time(mtime),
        .is_directory = false,
    };
}

kasumi::NodeRow make_directory(std::string path) {
    return kasumi::NodeRow{
        .path = std::move(path),
        .hash = {},
        .size = 0,
        .mtime = {},
        .is_directory = true,
    };
}

kasumi::Snapshot make_tree(std::initializer_list<kasumi::NodeRow> rows) {
    kasumi::Snapshot tree{.rows = {make_directory("")}};
    tree.rows.insert(tree.rows.end(), rows.begin(), rows.end());
    kasumi::finalize_snapshot(tree);
    return tree;
}

std::vector<std::uint8_t> hex_bytes(std::string_view text) {
    const auto nibble = [](char value) -> std::uint8_t {
        if (value >= '0' && value <= '9') {
            return static_cast<std::uint8_t>(value - '0');
        }
        return static_cast<std::uint8_t>(value - 'a' + 10);
    };
    EXPECT_EQ(text.size() % 2, 0U);
    std::vector<std::uint8_t> result;
    result.reserve(text.size() / 2);
    for (std::size_t index = 0; index < text.size(); index += 2) {
        result.push_back(static_cast<std::uint8_t>((nibble(text[index]) << 4) |
                                                   nibble(text[index + 1])));
    }
    return result;
}

kasumi::history::LoadedCommit load_commit(kasumi::history::Commit commit) {
    auto id = compute_id(commit);
    EXPECT_TRUE(id.has_value());
    if (!id) {
        return {};
    }
    return kasumi::history::LoadedCommit{*id, std::move(commit)};
}

std::vector<LoadedCommit> make_independent_heads(const Commit& base,
                                                 std::size_t count) {
    const auto base_id = compute_id(base).value();
    std::vector<LoadedCommit> heads;
    heads.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const auto number = std::to_string(i);
        const auto path =
            std::string("file-") + (i < 10 ? "0" : "") + number + ".txt";
        const auto commit = make_commit(
            base.height + 1, {base_id}, make_tree({make_file(path, number)}));
        EXPECT_TRUE(commit.has_value());
        if (!commit)
            return {};
        heads.push_back(load_commit(*commit));
    }
    return heads;
}

void expect_resolution_publishable(const Resolution& resolution) {
    EXPECT_LE(resolution.heads.size(), maximum_parent_count);
    const auto commit =
        make_commit(resolution.height + 1, resolution.heads, resolution.tree);
    EXPECT_TRUE(commit.has_value());
}

const kasumi::NodeRow* row_at(const kasumi::Snapshot& tree,
                              std::string_view path) {
    return kasumi::find_row(tree, path);
}

void expect_same_snapshot(const kasumi::Snapshot& left,
                          const kasumi::Snapshot& right) {
    ASSERT_EQ(left.rows.size(), right.rows.size());
    for (std::size_t i = 0; i < left.rows.size(); ++i) {
        EXPECT_EQ(left.rows[i].path, right.rows[i].path);
        EXPECT_EQ(left.rows[i].hash, right.rows[i].hash);
        EXPECT_EQ(left.rows[i].size, right.rows[i].size);
        EXPECT_EQ(left.rows[i].mtime, right.rows[i].mtime);
        EXPECT_EQ(left.rows[i].is_directory, right.rows[i].is_directory);
    }
}

TEST(HistoryTest, ValidCommitId) {
    EXPECT_TRUE(valid_commit_id(std::string(64, '0')));
    EXPECT_TRUE(valid_commit_id(std::string(64, 'a')));
    EXPECT_TRUE(valid_commit_id(std::string(64, 'f')));
    EXPECT_FALSE(valid_commit_id(std::string(63, 'a')));
    EXPECT_FALSE(valid_commit_id(std::string(65, 'a')));
    EXPECT_FALSE(valid_commit_id(std::string(64, 'A')));
    EXPECT_FALSE(valid_commit_id(std::string(64, ' ')));
}

TEST(HistoryTest, BootstrapDeterminism) {
    auto b1 = make_empty_bootstrap();
    ASSERT_TRUE(b1.has_value());
    EXPECT_EQ(b1->height, 0);
    EXPECT_TRUE(b1->parents.empty());

    auto b2 = make_empty_bootstrap();
    ASSERT_TRUE(b2.has_value());

    auto s1 = serialize(*b1);
    auto s2 = serialize(*b2);
    ASSERT_TRUE(s1.has_value());
    ASSERT_TRUE(s2.has_value());
    EXPECT_EQ(*s1, *s2);

    EXPECT_EQ(
        *s1,
        hex_bytes("4b434f4d0200000000000000000000000000000000000000004500000000000000"
                  "4b415355000000000000000000000000af1349b9f5f9a1a6a"
                  "0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
                  "000000000000000000000000000000000100000000"));

    auto id1 = compute_id(*b1);
    auto id2 = compute_id(*b2);
    ASSERT_TRUE(id1.has_value());
    ASSERT_TRUE(id2.has_value());
    EXPECT_EQ(
        *id1,
        "37969995ac87eae8c95862a4a8a4a94f00dd5092bf7be19df594af07bcff4ca1");
    EXPECT_EQ(*id2, *id1);
}

TEST(HistoryTest, BootstrapWithExplicitHeight) {
    auto snap = make_valid_snapshot();
    auto b = make_bootstrap(snap, 42);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->height, 42);
    EXPECT_TRUE(b->parents.empty());
}

TEST(HistoryTest, CommitCodecGoldenVectors) {
    const auto empty = make_empty_bootstrap();
    const auto with_file = make_bootstrap(
        make_tree({make_file("alpha.txt", "alpha", 123456789)}), 0);
    ASSERT_TRUE(empty.has_value() && with_file.has_value());
    const auto empty_id = compute_id(*empty);
    ASSERT_TRUE(empty_id.has_value());
    const auto one_parent = make_commit(
        1, {*empty_id}, make_tree({make_file("beta.txt", "beta", 223456789)}));
    const auto multiple_parent =
        make_commit(9,
                    {std::string(64, '0'), std::string(64, '1')},
                    make_tree({make_file("gamma.txt", "gamma", 323456789)}));
    ASSERT_TRUE(one_parent.has_value() && multiple_parent.has_value());

    const auto expect =
        [](const Commit& commit, std::string_view bytes, std::string_view id) {
            const auto encoded = serialize(commit);
            const auto actual_id = compute_id(commit);
            ASSERT_TRUE(encoded.has_value());
            ASSERT_TRUE(actual_id.has_value());
            EXPECT_EQ(*encoded, hex_bytes(bytes)) << id;
            EXPECT_EQ(*actual_id, id);
        };
    expect(*empty,
           "4b434f4d0200000000000000000000000000000000000000004500000000000000"
           "4b415355000000000000000000000000af1349b9f5f9a1a6a0404dea36dcc949"
           "9bcb25c9adc112b7cc9a93cae41f326200000000000000000000000000000000"
           "0100000000",
           "37969995ac87eae8c95862a4a8a4a94f00dd5092bf7be19df594af07bcff4ca1");
#if defined(_MSC_VER)
    expect(*with_file,
           "4b434f4d02000000000000000000000000000000000000000087000000000000004b41535500000000000000000000000035e462ba5dde50"
           "0fdaa4273bd553d2a3eb89984e51e322fdcb2465247449f69705000000000000000000000000000000010100000009000000616c7068612e"
           "747874644a9bc57c6063e2ba4028fa73ed585170ae7db8ac7723d32be49c021a0225f50500000000000000bccc5b07000000000000000000",
           "cad3bfbbd81e9c37b388b3258417d41a002f8d14d8f743156f47e7f7cd88c410");
    expect(*one_parent,
           "4b434f4d02010000000000000000000000000000000100000037969995ac87eae8c95862a4a8a4a94f00dd5092bf7be19df594af07bcff4c"
           "a186000000000000004b4153550100000000000000000000004bc2873777530dc7556a9788d558d522e1e15ff905766a1fc3d9e95775d2b7"
           "5104000000000000000000000000000000010100000008000000626574612e747874c607f0e66519ff41d34c1c8e2e312228c3cc358c0a5b"
           "75cef4b22cf8ed3875db0400000000000000bcad510d000000000000000000",
           "9fd9dac7ae04588e0dbee71f78e426b88d44562e68d0f030d21290bb304fb2a1");
    expect(*multiple_parent,
           "4b434f4d02090000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000"
           "00111111111111111111111111111111111111111111111111111111111111111187000000000000004b4153550900000000000000000000"
           "00b76e453e2e95d7e770a5760e46ef965d3373132bd225aa93c5dce717219ad4000500000000000000000000000000000001010000000900"
           "000067616d6d612e747874039b3fa6c7a5987c410ffe6d58ab194dfc98840263841bc7c949bdd4497fd5760500000000000000bc8e471300"
           "0000000000000000",
           "4dc7b87fb49ec1f1420b31d0ae8036cb9bb797ee1c160c13d4d5dd89abe6c662");
#else
    expect(*with_file,
           "4b434f4d02000000000000000000000000000000000000000087000000000000004b41535500000000000000000000000035e462ba5dde50"
           "0fdaa4273bd553d2a3eb89984e51e322fdcb2465247449f69705000000000000000000000000000000010100000009000000616c7068612e"
           "747874644a9bc57c6063e2ba4028fa73ed585170ae7db8ac7723d32be49c021a0225f5050000000000000015cd5b07000000000000000000",
           "2734919a604e32e8267013f8e2fbcf38c6934d1b37b633a4e47dee2af09f1860");
    expect(*one_parent,
           "4b434f4d02010000000000000000000000000000000100000037969995ac87eae8c95862a4a8a4a94f00dd5092bf7be19df594af07bcff4c"
           "a186000000000000004b4153550100000000000000000000004bc2873777530dc7556a9788d558d522e1e15ff905766a1fc3d9e95775d2b7"
           "5104000000000000000000000000000000010100000008000000626574612e747874c607f0e66519ff41d34c1c8e2e312228c3cc358c0a5b"
           "75cef4b22cf8ed3875db040000000000000015ae510d000000000000000000",
           "1510b858cccd8f47b1b9cdc97f122e0f060f1a7f74482eee779a55ab772417e1");
    expect(*multiple_parent,
           "4b434f4d02090000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000"
           "00111111111111111111111111111111111111111111111111111111111111111187000000000000004b4153550900000000000000000000"
           "00b76e453e2e95d7e770a5760e46ef965d3373132bd225aa93c5dce717219ad4000500000000000000000000000000000001010000000900"
           "000067616d6d612e747874039b3fa6c7a5987c410ffe6d58ab194dfc98840263841bc7c949bdd4497fd5760500000000000000158f471300"
           "0000000000000000",
           "16baad7c4a64234d153659f4357ec1c8d5472c54a5d6f92773c1a1aff7226db8");
#endif
}

TEST(HistoryTest, MakeCommit) {
    auto snap = make_valid_snapshot();
    std::string p1 = std::string(64, 'a');
    std::string p2 = std::string(64, 'b');
    auto c = make_commit(1, {p2, p1}, snap);
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(c->parents.size(), 2);
    EXPECT_EQ(c->parents[0], p1);
    EXPECT_EQ(c->parents[1], p2);
}

TEST(HistoryTest, MakeCommitErrors) {
    auto snap = make_valid_snapshot();
    std::string p1 = std::string(64, 'a');
    auto c1 = make_commit(1, {p1, p1}, snap);
    EXPECT_FALSE(c1.has_value());
    EXPECT_EQ(c1.error().code, ErrorCode::InvalidParent);

    auto c2 = make_commit(1, {"invalid"}, snap);
    EXPECT_FALSE(c2.has_value());
    EXPECT_EQ(c2.error().code, ErrorCode::InvalidParent);

    auto c3 = make_commit(1, {p1}, make_empty_snapshot());
    EXPECT_FALSE(c3.has_value());
    EXPECT_EQ(c3.error().code, ErrorCode::InvalidSnapshot);

    std::vector<std::string> many_parents(maximum_parent_count + 1,
                                          std::string(64, 'a'));
    auto c4 = make_commit(1, many_parents, snap);
    EXPECT_FALSE(c4.has_value());
    EXPECT_EQ(c4.error().code, ErrorCode::LimitExceeded);
}

TEST(HistoryTest, CodecRoundTrip) {
    auto snap = make_valid_snapshot();
    std::string p1 = std::string(64, 'a');
    auto c = make_commit(1, {p1}, snap);
    ASSERT_TRUE(c.has_value());

    auto s = serialize(*c);
    ASSERT_TRUE(s.has_value());

    auto d = deserialize(*s);
    ASSERT_TRUE(d.has_value());

    EXPECT_EQ(d->height, c->height);
    EXPECT_EQ(d->parents, c->parents);
    EXPECT_EQ(d->tree.rows.size(), c->tree.rows.size());
}

TEST(HistoryTest, CanonicalTimestampRoundTripsWithoutChangingBytes) {
    const auto commit = make_bootstrap(
        make_tree({make_file("timestamped.txt", "contents", 123456789)}),
        0,
        42);
    ASSERT_TRUE(commit.has_value());

    const auto encoded = serialize(*commit);
    ASSERT_TRUE(encoded.has_value());
    const auto decoded = deserialize(*encoded);
    ASSERT_TRUE(decoded.has_value());
    const auto reencoded = serialize(*decoded);
    ASSERT_TRUE(reencoded.has_value());

    EXPECT_EQ(*reencoded, *encoded);
    EXPECT_EQ(decoded->created_at, 42);
    ASSERT_EQ(decoded->tree.rows.size(), commit->tree.rows.size());
    EXPECT_EQ(decoded->tree.rows.back().mtime,
              commit->tree.rows.back().mtime);
}

TEST(HistoryTest, CodecErrors) {
    auto snap = make_valid_snapshot();
    auto c = make_commit(1, {}, snap);
    ASSERT_TRUE(c.has_value());
    auto s = serialize(*c);
    ASSERT_TRUE(s.has_value());

    std::vector<uint8_t> bad_magic = *s;
    bad_magic[0] = 'X';
    EXPECT_EQ(deserialize(bad_magic).error().code, ErrorCode::InvalidEncoding);

    std::vector<uint8_t> bad_version = *s;
    bad_version[4] = 99;
    EXPECT_EQ(deserialize(bad_version).error().code,
              ErrorCode::UnsupportedVersion);

    std::vector<uint8_t> trunc_header = *s;
    trunc_header.resize(3);
    EXPECT_EQ(deserialize(trunc_header).error().code,
              ErrorCode::InvalidEncoding);

    std::vector<uint8_t> trunc_tree = *s;
    trunc_tree.resize(trunc_tree.size() - 1);
    EXPECT_EQ(deserialize(trunc_tree).error().code, ErrorCode::InvalidEncoding);

    std::vector<uint8_t> trailing_bytes = *s;
    trailing_bytes.push_back(0);
    EXPECT_EQ(deserialize(trailing_bytes).error().code,
              ErrorCode::InvalidEncoding);

    std::vector<uint8_t> bad_height = *s;
    bad_height[5] = 99;
    EXPECT_EQ(deserialize(bad_height).error().code, ErrorCode::InvalidEncoding);
}

TEST(HistoryTest, ResolveDagValidation) {
    auto b1 = make_empty_bootstrap();
    ASSERT_TRUE(b1.has_value());
    auto id1 = compute_id(*b1).value();
    LoadedCommit lc1{id1, *b1};

    auto b2 = make_empty_bootstrap();
    auto id2 = compute_id(*b2).value();
    LoadedCommit lc2{id2, *b2};

    EXPECT_EQ(resolve(std::vector<LoadedCommit>{lc1, lc1},
                      std::vector<std::string>{id1})
                  .error()
                  .code,
              ErrorCode::DuplicateCommit);

    auto c3 = make_commit(1, {id2}, make_valid_snapshot()).value();
    auto id3 = compute_id(c3).value();
    LoadedCommit lc3{id3, c3};
    EXPECT_EQ(
        resolve(std::vector<LoadedCommit>{lc3}, std::vector<std::string>{id3})
            .error()
            .code,
        ErrorCode::MissingParent);

    LoadedCommit lc_bad_id{
        "0000000000000000000000000000000000000000000000000000000000000000",
        *b1};
    EXPECT_EQ(resolve(std::vector<LoadedCommit>{lc_bad_id},
                      std::vector<std::string>{lc_bad_id.id})
                  .error()
                  .code,
              ErrorCode::InvalidCommitId);

    auto c4 = make_commit(2, {id1}, make_valid_snapshot()).value();
    auto id4 = compute_id(c4).value();
    LoadedCommit lc4{id4, c4};
    EXPECT_EQ(resolve(std::vector<LoadedCommit>{lc1, lc4},
                      std::vector<std::string>{id4})
                  .error()
                  .code,
              ErrorCode::HeightMismatch);

    EXPECT_EQ(
        resolve(std::vector<LoadedCommit>{lc1}, std::vector<std::string>{})
            .error()
            .code,
        ErrorCode::InvalidHead);

    EXPECT_EQ(
        resolve(std::vector<LoadedCommit>{lc1}, std::vector<std::string>{id3})
            .error()
            .code,
        ErrorCode::InvalidHead);
}

TEST(HistoryTest, HeadFilteringAndMergeBase) {
    auto b1 = make_empty_bootstrap();
    auto id1 = compute_id(*b1).value();
    LoadedCommit lc1{id1, *b1};

    auto c2 = make_commit(1, {id1}, make_custom_snapshot(1)).value();
    auto id2 = compute_id(c2).value();
    LoadedCommit lc2{id2, c2};

    auto c3 = make_commit(1, {id1}, make_custom_snapshot(2)).value();
    auto id3 = compute_id(c3).value();
    LoadedCommit lc3{id3, c3};

    auto res_stale = resolve(std::vector<LoadedCommit>{lc1, lc2},
                             std::vector<std::string>{id1, id2});
    ASSERT_TRUE(res_stale.has_value());
    expect_resolution_publishable(*res_stale);
    EXPECT_EQ(res_stale->heads.size(), 1);
    EXPECT_EQ(res_stale->heads[0], id2);

    auto res_common = resolve(std::vector<LoadedCommit>{lc1, lc2, lc3},
                              std::vector<std::string>{id2, id3});
    ASSERT_TRUE(res_common.has_value());
    expect_resolution_publishable(*res_common);
    EXPECT_FALSE(res_common->has_conflicts);
    EXPECT_EQ(res_common->heads.size(), 2);
    EXPECT_EQ(res_common->height, 1);
}

TEST(HistoryTest, AmbiguousMergeBase) {
    auto a = make_empty_bootstrap().value();
    auto ida = compute_id(a).value();
    LoadedCommit lca{ida, a};

    auto b = make_commit(1, {ida}, make_custom_snapshot(1)).value();
    auto idb = compute_id(b).value();
    LoadedCommit lcb{idb, b};

    auto c = make_commit(1, {ida}, make_custom_snapshot(2)).value();
    auto idc = compute_id(c).value();
    LoadedCommit lcc{idc, c};

    auto d = make_commit(2, {idb, idc}, make_custom_snapshot(3)).value();
    auto idd = compute_id(d).value();
    LoadedCommit lcd{idd, d};

    auto e = make_commit(2, {idb, idc}, make_custom_snapshot(4)).value();
    auto ide = compute_id(e).value();
    LoadedCommit lce{ide, e};

    auto res = resolve(std::vector<LoadedCommit>{lca, lcb, lcc, lcd, lce},
                       std::vector<std::string>{idd, ide});
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::AmbiguousMergeBase);
}

TEST(HistoryTest, MergeConflict_FileFile) {
    auto b1 = make_empty_bootstrap();
    auto id1 = compute_id(*b1).value();
    LoadedCommit lc1{id1, *b1};

    kasumi::Snapshot s2 = make_custom_snapshot(0);
    s2.rows.push_back(kasumi::NodeRow{
        .path = "file.txt",
        .hash = kasumi::hasher::hash_string("A"),
        .size = 1,
        .mtime = canonical_time(0),
        .is_directory = false,
    });
    kasumi::finalize_snapshot(s2);
    auto c2 = make_commit(1, {id1}, s2).value();
    auto id2 = compute_id(c2).value();
    LoadedCommit lc2{id2, c2};

    kasumi::Snapshot s3 = make_custom_snapshot(0);
    s3.rows.push_back(kasumi::NodeRow{
        .path = "file.txt",
        .hash = kasumi::hasher::hash_string("B"),
        .size = 1,
        .mtime = canonical_time(0),
        .is_directory = false,
    });
    kasumi::finalize_snapshot(s3);
    auto c3 = make_commit(1, {id1}, s3).value();
    auto id3 = compute_id(c3).value();
    LoadedCommit lc3{id3, c3};

    auto res = resolve(std::vector<LoadedCommit>{lc1, lc2, lc3},
                       std::vector<std::string>{id2, id3});
    ASSERT_TRUE(res.has_value());
    expect_resolution_publishable(*res);
    EXPECT_TRUE(res->has_conflicts);

    bool found_principal = false;
    bool found_conflict = false;

    std::string expected_principal_head = id2 < id3 ? id2 : id3;
    std::string expected_conflict_head = id2 < id3 ? id3 : id2;

    for (const auto& row : res->tree.rows) {
        if (row.path == "file.txt") {
            found_principal = true;
            EXPECT_EQ(row.hash,
                      kasumi::hasher::hash_string(
                          expected_principal_head == id2 ? "A" : "B"));
        }
        if (row.path ==
            "file.txt.kasumiconflict_" + expected_conflict_head.substr(0, 12))
            found_conflict = true;
    }
    EXPECT_TRUE(found_principal);
    EXPECT_TRUE(found_conflict);
}

TEST(HistoryTest, MergeConflict_DeleteModify) {
    kasumi::Snapshot s1 = make_custom_snapshot(0);
    s1.rows.push_back(kasumi::NodeRow{
        .path = "file.txt",
        .hash = kasumi::hasher::hash_string("A"),
        .size = 1,
        .mtime = canonical_time(0),
        .is_directory = false,
    });
    kasumi::finalize_snapshot(s1);
    auto b1 = make_bootstrap(s1, 0).value();
    auto id1 = compute_id(b1).value();
    LoadedCommit lc1{id1, b1};

    kasumi::Snapshot s2 = make_custom_snapshot(0);
    s2.rows.push_back(kasumi::NodeRow{
        .path = "file.txt",
        .hash = kasumi::hasher::hash_string("B"),
        .size = 1,
        .mtime = canonical_time(0),
        .is_directory = false,
    });
    kasumi::finalize_snapshot(s2);
    auto c2 = make_commit(1, {id1}, s2).value();
    auto id2 = compute_id(c2).value();
    LoadedCommit lc2{id2, c2};

    kasumi::Snapshot s3 = make_custom_snapshot(0);
    auto c3 = make_commit(1, {id1}, s3).value();
    auto id3 = compute_id(c3).value();
    LoadedCommit lc3{id3, c3};

    auto res = resolve(std::vector<LoadedCommit>{lc1, lc2, lc3},
                       std::vector<std::string>{id2, id3});
    ASSERT_TRUE(res.has_value());
    expect_resolution_publishable(*res);
    EXPECT_TRUE(res->has_conflicts);

    bool found_principal = false;
    for (const auto& row : res->tree.rows) {
        if (row.path == "file.txt") {
            found_principal = true;
            EXPECT_EQ(row.hash, kasumi::hasher::hash_string("B"));
        }
        if (row.path.find("kasumiconflict") != std::string::npos) {
            FAIL() << "Absent should not generate conflict path";
        }
    }
    EXPECT_TRUE(found_principal);
}

TEST(HistoryTest, MergeConflict_FileDirectory) {
    auto b1 = make_empty_bootstrap();
    auto id1 = compute_id(*b1).value();
    LoadedCommit lc1{id1, *b1};

    kasumi::Snapshot s2 = make_custom_snapshot(0);
    s2.rows.push_back(kasumi::NodeRow{
        .path = "shared",
        .hash = {},
        .size = 0,
        .mtime = {},
        .is_directory = true,
    });
    s2.rows.push_back(make_file("shared/item.txt", "directory content"));
    kasumi::finalize_snapshot(s2);
    auto c2 = make_commit(1, {id1}, s2).value();
    auto id2 = compute_id(c2).value();
    LoadedCommit lc2{id2, c2};

    kasumi::Snapshot s3 = make_custom_snapshot(0);
    s3.rows.push_back(kasumi::NodeRow{
        .path = "shared",
        .hash = kasumi::hasher::hash_string("A"),
        .size = 1,
        .mtime = canonical_time(0),
        .is_directory = false,
    });
    kasumi::finalize_snapshot(s3);
    auto c3 = make_commit(1, {id1}, s3).value();
    auto id3 = compute_id(c3).value();
    LoadedCommit lc3{id3, c3};

    auto res = resolve(std::vector<LoadedCommit>{lc1, lc2, lc3},
                       std::vector<std::string>{id2, id3});
    ASSERT_TRUE(res.has_value());
    expect_resolution_publishable(*res);
    EXPECT_TRUE(res->has_conflicts);

    bool found_dir = false;
    bool found_file_conflict = false;
    for (const auto& row : res->tree.rows) {
        if (row.path == "shared") {
            found_dir = true;
            EXPECT_TRUE(row.is_directory);
        }
        if (row.path == "shared.kasumiconflict_" + id3.substr(0, 12)) {
            found_file_conflict = true;
            EXPECT_FALSE(row.is_directory);
        }
    }
    EXPECT_TRUE(found_dir);
    EXPECT_TRUE(found_file_conflict);
}

TEST(HistoryTest, Merge_SameState_DifferentMtime) {
    auto b1 = make_empty_bootstrap();
    auto id1 = compute_id(*b1).value();
    LoadedCommit lc1{id1, *b1};

    kasumi::Snapshot s2 = make_custom_snapshot(0);
    s2.rows.push_back(kasumi::NodeRow{
        .path = "file.txt",
        .hash = kasumi::hasher::hash_string("A"),
        .size = 1,
        .mtime = canonical_time(100),
        .is_directory = false,
    });
    kasumi::finalize_snapshot(s2);
    auto c2 = make_commit(1, {id1}, s2).value();
    auto id2 = compute_id(c2).value();
    LoadedCommit lc2{id2, c2};

    kasumi::Snapshot s3 = make_custom_snapshot(0);
    s3.rows.push_back(kasumi::NodeRow{
        .path = "file.txt",
        .hash = kasumi::hasher::hash_string("A"),
        .size = 1,
        .mtime = canonical_time(200),
        .is_directory = false,
    });
    kasumi::finalize_snapshot(s3);
    auto c3 = make_commit(1, {id1}, s3).value();
    auto id3 = compute_id(c3).value();
    LoadedCommit lc3{id3, c3};

    auto res = resolve(std::vector<LoadedCommit>{lc1, lc2, lc3},
                       std::vector<std::string>{id2, id3});
    ASSERT_TRUE(res.has_value());
    EXPECT_FALSE(res->has_conflicts);

    bool found_file = false;
    for (const auto& row : res->tree.rows) {
        if (row.path == "file.txt") {
            found_file = true;
            EXPECT_EQ(row.mtime, canonical_time(200));
        }
    }
    EXPECT_TRUE(found_file);
}

TEST(HistoryTest, DirectoryDeleteVersusSubtreeModifyPreservesChangedSubtree) {
    const auto base_tree = make_tree({
        make_directory("docs"),
        make_file("docs/base.txt", "base"),
    });
    const auto base = make_bootstrap(base_tree, 0).value();
    const auto base_id = compute_id(base).value();

    const auto deleted = make_commit(1, {base_id}, make_tree({})).value();
    const auto changed = make_commit(1,
                                     {base_id},
                                     make_tree({
                                         make_directory("docs"),
                                         make_file("docs/new.txt", "new"),
                                     }))
                             .value();
    const auto deleted_loaded = load_commit(deleted);
    const auto changed_loaded = load_commit(changed);

    auto resolve_in_order = [&](bool reverse) {
        std::vector<LoadedCommit> loaded{load_commit(base)};
        loaded.push_back(reverse ? changed_loaded : deleted_loaded);
        loaded.push_back(reverse ? deleted_loaded : changed_loaded);
        std::vector<std::string> heads{
            reverse ? changed_loaded.id : deleted_loaded.id,
            reverse ? deleted_loaded.id : changed_loaded.id,
        };
        return resolve(loaded, heads);
    };

    const auto first = resolve_in_order(false);
    const auto second = resolve_in_order(true);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    expect_resolution_publishable(*first);
    expect_resolution_publishable(*second);
    EXPECT_TRUE(first->has_conflicts);
    EXPECT_TRUE(second->has_conflicts);
    ASSERT_NE(row_at(first->tree, "docs"), nullptr);
    EXPECT_TRUE(row_at(first->tree, "docs")->is_directory);
    EXPECT_NE(row_at(first->tree, "docs/new.txt"), nullptr);
    EXPECT_EQ(row_at(first->tree, "docs/base.txt"), nullptr);
    EXPECT_TRUE(valid_snapshot(first->tree, false));
    EXPECT_TRUE(valid_snapshot(second->tree, false));
    expect_same_snapshot(first->tree, second->tree);
}

TEST(HistoryTest, DirectoryDeleteVersusUnchangedAppliesDeleteWithoutConflict) {
    const auto base_tree = make_tree({
        make_directory("docs"),
        make_file("docs/a.txt", "a"),
    });
    const auto base = make_bootstrap(base_tree, 0).value();
    const auto base_id = compute_id(base).value();
    const auto deleted = make_commit(1, {base_id}, make_tree({})).value();
    const auto unchanged = make_commit(1, {base_id}, base_tree).value();

    const auto result = resolve(
        std::vector<LoadedCommit>{
            load_commit(base), load_commit(deleted), load_commit(unchanged)},
        std::vector<std::string>{compute_id(deleted).value(),
                                 compute_id(unchanged).value()});
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_conflicts);
    EXPECT_EQ(row_at(result->tree, "docs"), nullptr);
    EXPECT_EQ(row_at(result->tree, "docs/a.txt"), nullptr);
}

TEST(HistoryTest, FileVersusModifiedSubtreeKeepsDirectoryAndMovesFile) {
    const auto base_tree = make_tree({
        make_directory("shared"),
        make_file("shared/item.txt", "X"),
    });
    const auto base = make_bootstrap(base_tree, 0).value();
    const auto base_id = compute_id(base).value();
    const auto file_head =
        make_commit(1, {base_id}, make_tree({make_file("shared", "F")}))
            .value();
    const auto directory_head =
        make_commit(1,
                    {base_id},
                    make_tree({
                        make_directory("shared"),
                        make_file("shared/item.txt", "Y"),
                    }))
            .value();
    const auto file_loaded = load_commit(file_head);
    const auto directory_loaded = load_commit(directory_head);

    for (const bool reverse : {false, true}) {
        const auto& first = reverse ? file_loaded : directory_loaded;
        const auto& second = reverse ? directory_loaded : file_loaded;
        const auto result =
            resolve(std::vector<LoadedCommit>{load_commit(base), first, second},
                    std::vector<std::string>{first.id, second.id});
        ASSERT_TRUE(result.has_value());
        expect_resolution_publishable(*result);
        EXPECT_TRUE(result->has_conflicts);
        ASSERT_NE(row_at(result->tree, "shared"), nullptr);
        EXPECT_TRUE(row_at(result->tree, "shared")->is_directory);
        ASSERT_NE(row_at(result->tree, "shared/item.txt"), nullptr);
        EXPECT_EQ(row_at(result->tree, "shared/item.txt")->hash,
                  kasumi::hasher::hash_string("Y"));
        const auto* conflict =
            row_at(result->tree,
                   "shared.kasumiconflict_" + file_loaded.id.substr(0, 12));
        ASSERT_NE(conflict, nullptr);
        EXPECT_FALSE(conflict->is_directory);
        EXPECT_EQ(conflict->hash, kasumi::hasher::hash_string("F"));
    }
}

TEST(HistoryTest, IndependentSubtreeChangesAreCombined) {
    const auto base_tree = make_tree({make_directory("docs")});
    const auto base = make_bootstrap(base_tree, 0).value();
    const auto base_id = compute_id(base).value();
    const auto left = make_commit(1,
                                  {base_id},
                                  make_tree({
                                      make_directory("docs"),
                                      make_file("docs/a.txt", "A"),
                                  }))
                          .value();
    const auto right = make_commit(1,
                                   {base_id},
                                   make_tree({
                                       make_directory("docs"),
                                       make_file("docs/b.txt", "B"),
                                   }))
                           .value();

    const auto result = resolve(
        std::vector<LoadedCommit>{
            load_commit(base), load_commit(left), load_commit(right)},
        std::vector<std::string>{compute_id(left).value(),
                                 compute_id(right).value()});
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_conflicts);
    EXPECT_EQ(row_at(result->tree, "docs/a.txt")->hash,
              kasumi::hasher::hash_string("A"));
    EXPECT_EQ(row_at(result->tree, "docs/b.txt")->hash,
              kasumi::hasher::hash_string("B"));
}

TEST(HistoryTest, ConflictPathCollisionUsesSequentialSuffixes) {
    const auto base = make_empty_bootstrap().value();
    const auto base_id = compute_id(base).value();
    const auto right =
        make_commit(1, {base_id}, make_tree({make_file("notes.txt", "right")}))
            .value();
    const auto right_loaded = load_commit(right);
    const auto collision =
        "notes.txt.kasumiconflict_" + right_loaded.id.substr(0, 12);
    const auto collision_one = collision + ".1";

    Commit left;
    LoadedCommit left_loaded;
    for (std::size_t nonce = 0; nonce < 4096; ++nonce) {
        left = make_commit(
                   1,
                   {base_id},
                   make_tree({
                       make_file("notes.txt", "left" + std::to_string(nonce)),
                       make_file(collision, "original"),
                       make_file(collision_one, "original one"),
                   }))
                   .value();
        left_loaded = load_commit(left);
        if (left_loaded.id < right_loaded.id) {
            break;
        }
    }
    ASSERT_LT(left_loaded.id, right_loaded.id);

    const auto result = resolve(
        std::vector<LoadedCommit>{load_commit(base), left_loaded, right_loaded},
        std::vector<std::string>{left_loaded.id, right_loaded.id});
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->has_conflicts);
    EXPECT_EQ(row_at(result->tree, collision)->hash,
              kasumi::hasher::hash_string("original"));
    EXPECT_EQ(row_at(result->tree, collision_one)->hash,
              kasumi::hasher::hash_string("original one"));
    const auto* conflict = row_at(result->tree, collision + ".2");
    ASSERT_NE(conflict, nullptr);
    EXPECT_EQ(conflict->hash, kasumi::hasher::hash_string("right"));
}

TEST(HistoryTest, ThreeVariantsAndInputPermutationsAreDeterministic) {
    const auto base = make_empty_bootstrap().value();
    const auto base_id = compute_id(base).value();
    std::vector<LoadedCommit> heads;
    for (const auto& content :
         {std::string("A"), std::string("B"), std::string("C")}) {
        heads.push_back(load_commit(
            make_commit(
                1, {base_id}, make_tree({make_file("file.txt", content)}))
                .value()));
    }

    std::vector<std::size_t> order{0, 1, 2};
    std::vector<uint8_t> expected_bytes;
    std::string expected_id;
    do {
        std::vector<LoadedCommit> loaded{load_commit(base)};
        std::vector<std::string> marked;
        for (const auto index : order) {
            loaded.push_back(heads[index]);
            marked.push_back(heads[index].id);
        }
        const auto result = resolve(loaded, marked);
        ASSERT_TRUE(result.has_value());
        expect_resolution_publishable(*result);
        EXPECT_TRUE(result->has_conflicts);
        EXPECT_EQ(row_at(result->tree, "file.txt")->hash,
                  kasumi::hasher::hash_string(
                      result->heads.front() == heads[0].id   ? "A"
                      : result->heads.front() == heads[1].id ? "B"
                                                             : "C"));

        auto merge =
            make_commit(result->height + 1, result->heads, result->tree);
        ASSERT_TRUE(merge.has_value());
        auto bytes = serialize(*merge);
        auto id = compute_id(*merge);
        ASSERT_TRUE(bytes.has_value());
        ASSERT_TRUE(id.has_value());
        if (expected_bytes.empty()) {
            expected_bytes = *bytes;
            expected_id = *id;
        } else {
            EXPECT_EQ(*bytes, expected_bytes);
            EXPECT_EQ(*id, expected_id);
        }
    } while (std::next_permutation(order.begin(), order.end()));
}

TEST(HistoryTest, MergeIsIdempotentWhenMergeCommitIsMarked) {
    const auto base = make_empty_bootstrap().value();
    const auto base_id = compute_id(base).value();
    const auto left =
        make_commit(1, {base_id}, make_tree({make_file("file.txt", "A")}))
            .value();
    const auto right =
        make_commit(1, {base_id}, make_tree({make_file("file.txt", "B")}))
            .value();
    const auto first = resolve(
        std::vector<LoadedCommit>{
            load_commit(base), load_commit(left), load_commit(right)},
        std::vector<std::string>{compute_id(left).value(),
                                 compute_id(right).value()});
    ASSERT_TRUE(first.has_value());
    const auto merge =
        make_commit(first->height + 1, first->heads, first->tree);
    ASSERT_TRUE(merge.has_value());
    const auto merge_loaded = load_commit(*merge);

    const auto second =
        resolve(std::vector<LoadedCommit>{load_commit(base),
                                          load_commit(left),
                                          load_commit(right),
                                          merge_loaded},
                std::vector<std::string>{compute_id(left).value(),
                                         compute_id(right).value(),
                                         merge_loaded.id});
    ASSERT_TRUE(second.has_value());
    ASSERT_EQ(second->heads, std::vector<std::string>{merge_loaded.id});
    EXPECT_FALSE(second->has_conflicts);
    expect_same_snapshot(first->tree, second->tree);
}

TEST(HistoryTest, StructuralValidationRejectsMalformedTreesAtEveryBoundary) {
    const auto malformed = make_tree({
        make_file("shared", "file"),
        make_file("shared/item.txt", "child"),
    });
    EXPECT_EQ(make_commit(0, {}, malformed).error().code,
              ErrorCode::InvalidSnapshot);

    const Commit raw{.height = 0, .parents = {}, .tree = malformed};
    EXPECT_EQ(serialize(raw).error().code, ErrorCode::InvalidSnapshot);

    const LoadedCommit loaded{std::string(64, '0'), raw};
    const auto resolved = resolve(std::vector<LoadedCommit>{loaded},
                                  std::vector<std::string>{loaded.id});
    ASSERT_FALSE(resolved.has_value());
    EXPECT_EQ(resolved.error().code, ErrorCode::InvalidSnapshot);

    auto missing_parent = make_tree({make_file("missing/child.txt", "child")});
    const Commit missing_parent_commit{
        .height = 0, .parents = {}, .tree = missing_parent};
    EXPECT_EQ(serialize(missing_parent_commit).error().code,
              ErrorCode::InvalidSnapshot);
}

TEST(HistoryTest,
     CodecRejectsTotalAndTreeLimitsWithoutRepeatedLargeAllocations) {
    const auto commit = make_empty_bootstrap().value();
    const auto bytes = serialize(commit).value();
    std::vector<uint8_t> forged_tree_size = bytes;
    const auto too_large = maximum_commit_plaintext_size + 1;
    for (std::size_t i = 0; i < sizeof(too_large); ++i) {
        forged_tree_size[25 + i] = static_cast<uint8_t>(too_large >> (i * 8));
    }
    EXPECT_EQ(deserialize(forged_tree_size).error().code,
              ErrorCode::LimitExceeded);

    std::vector<uint8_t> oversized(maximum_commit_plaintext_size + 1);
    EXPECT_EQ(deserialize(oversized).error().code, ErrorCode::LimitExceeded);
}

TEST(HistoryTest, Resolve32LogicalHeadsIsPublishable) {
    const auto base = make_empty_bootstrap().value();
    const auto heads = make_independent_heads(base, maximum_parent_count);
    std::vector<LoadedCommit> loaded{load_commit(base)};
    std::vector<std::string> marked;
    for (const auto& head : heads) {
        loaded.push_back(head);
        marked.push_back(head.id);
    }

    const auto result = resolve(loaded, marked);
    ASSERT_TRUE(result.has_value());
    expect_resolution_publishable(*result);
    EXPECT_EQ(result->heads.size(), maximum_parent_count);
    EXPECT_TRUE(std::ranges::is_sorted(result->heads));
    EXPECT_FALSE(result->has_conflicts);
    for (std::size_t i = 0; i < maximum_parent_count; ++i) {
        const auto number = std::to_string(i);
        EXPECT_NE(row_at(result->tree,
                         std::string("file-") + (i < 10 ? "0" : "") + number +
                             ".txt"),
                  nullptr);
    }
}

TEST(HistoryTest, Resolve33LogicalHeadsFailsClosed) {
    const auto base = make_empty_bootstrap().value();
    const auto heads = make_independent_heads(base, maximum_parent_count + 1);
    std::vector<LoadedCommit> loaded{load_commit(base)};
    std::vector<std::string> marked;
    for (const auto& head : heads) {
        loaded.push_back(head);
        marked.push_back(head.id);
    }

    const auto result = resolve(loaded, marked);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::LimitExceeded);
    EXPECT_NE(result.error().detail.find("heads lógicas"),
              std::string::npos);
    EXPECT_NE(result.error().detail.find("merge"), std::string::npos);
    EXPECT_NE(result.error().detail.find("limite"), std::string::npos);
}

TEST(HistoryTest, MoreThan32AncestralMarkersLeaveOneLogicalHead) {
    const auto base = make_empty_bootstrap().value();
    const auto base_id = compute_id(base).value();
    std::vector<LoadedCommit> loaded{load_commit(base)};
    std::vector<std::string> marked{base_id};
    auto parent = base_id;
    LoadedCommit last;
    for (std::size_t i = 0; i < 40; ++i) {
        const auto commit = make_commit(
            i + 1, {parent}, make_custom_snapshot(static_cast<int>(i + 1)));
        ASSERT_TRUE(commit.has_value());
        last = load_commit(*commit);
        loaded.push_back(last);
        marked.push_back(last.id);
        parent = last.id;
    }

    const auto result = resolve(loaded, marked);
    ASSERT_TRUE(result.has_value());
    expect_resolution_publishable(*result);
    ASSERT_EQ(result->heads.size(), 1);
    EXPECT_EQ(result->heads.front(), last.id);
}

namespace {

std::vector<std::uint8_t>
forge_commit_with_component(std::string_view component_name) {
    std::vector<std::uint8_t> tree;
    tree.insert(tree.end(), {'K', 'A', 'S', 'U'});
    tree.resize(tree.size() + 8, 0); // height: 0
    tree.resize(tree.size() + 4, 0); // root name len: 0
    tree.resize(tree.size() + 32, 0); // root hash
    tree.resize(tree.size() + 8, 0); // root size
    tree.resize(tree.size() + 8, 0); // root nanos
    tree.push_back(1); // root is_directory
    tree.push_back(1); // root children count = 1
    tree.push_back(0);
    tree.push_back(0);
    tree.push_back(0);

    const auto name_len = static_cast<std::uint32_t>(component_name.size());
    tree.push_back(static_cast<std::uint8_t>(name_len & 0xFF));
    tree.push_back(static_cast<std::uint8_t>((name_len >> 8) & 0xFF));
    tree.push_back(static_cast<std::uint8_t>((name_len >> 16) & 0xFF));
    tree.push_back(static_cast<std::uint8_t>((name_len >> 24) & 0xFF));
    tree.insert(tree.end(), component_name.begin(), component_name.end());
    tree.resize(tree.size() + 32, 0); // child hash
    tree.resize(tree.size() + 8, 0); // child size
    tree.resize(tree.size() + 8, 0); // child nanos
    tree.push_back(0); // child is_directory = 0
    tree.resize(tree.size() + 4, 0); // child children count = 0

    std::vector<std::uint8_t> commit;
    commit.insert(commit.end(), {'K', 'C', 'O', 'M'});
    commit.push_back(2); // version = 2
    commit.resize(commit.size() + 8, 0); // height: 0
    commit.resize(commit.size() + 8, 0); // created_at: 0
    commit.resize(commit.size() + 4, 0); // parent_count: 0
    const auto tree_size = static_cast<std::uint64_t>(tree.size());
    for (std::size_t i = 0; i < 8; ++i) {
        commit.push_back(
            static_cast<std::uint8_t>((tree_size >> (i * 8)) & 0xFF));
    }
    commit.insert(commit.end(), tree.begin(), tree.end());
    return commit;
}

} // namespace

TEST(HistoryDeserializationTest, RejectsNonPortableTreeComponents) {
    // Sanity check: valid component deserializes without errors
    const auto valid_payload = forge_commit_with_component("valid.txt");
    const auto valid_commit = deserialize(valid_payload);
    ASSERT_TRUE(valid_commit.has_value());
    EXPECT_EQ(valid_commit->tree.rows.size(), 2U);

    // Rejects backslash component
    const auto backslash_payload = forge_commit_with_component("a\\b");
    const auto backslash_commit = deserialize(backslash_payload);
    ASSERT_FALSE(backslash_commit.has_value());
    EXPECT_EQ(backslash_commit.error().code, ErrorCode::InvalidEncoding);

    // Rejects colon component
    const auto colon_payload = forge_commit_with_component("a:b");
    const auto colon_commit = deserialize(colon_payload);
    ASSERT_FALSE(colon_commit.has_value());
    EXPECT_EQ(colon_commit.error().code, ErrorCode::InvalidEncoding);

    // Rejects reserved device component
    const auto con_payload = forge_commit_with_component("CON");
    const auto con_commit = deserialize(con_payload);
    ASSERT_FALSE(con_commit.has_value());
    EXPECT_EQ(con_commit.error().code, ErrorCode::InvalidEncoding);

    const auto con_txt_payload = forge_commit_with_component("con.txt");
    const auto con_txt_commit = deserialize(con_txt_payload);
    ASSERT_FALSE(con_txt_commit.has_value());
    EXPECT_EQ(con_txt_commit.error().code, ErrorCode::InvalidEncoding);

    // Rejects trailing dot and trailing space
    const auto dot_payload = forge_commit_with_component("file.");
    const auto dot_commit = deserialize(dot_payload);
    ASSERT_FALSE(dot_commit.has_value());
    EXPECT_EQ(dot_commit.error().code, ErrorCode::InvalidEncoding);

    const auto space_payload = forge_commit_with_component("file ");
    const auto space_commit = deserialize(space_payload);
    ASSERT_FALSE(space_commit.has_value());
    EXPECT_EQ(space_commit.error().code, ErrorCode::InvalidEncoding);

    // Rejects oversized component (> 255 bytes)
    const auto oversized_payload =
        forge_commit_with_component(std::string(256, 'x'));
    const auto oversized_commit = deserialize(oversized_payload);
    ASSERT_FALSE(oversized_commit.has_value());
    EXPECT_EQ(oversized_commit.error().code, ErrorCode::InvalidEncoding);
}

TEST(HistoryTest, RejectsUnicodeCaseEquivalentSnapshotInCommit) {
    const auto colliding_tree = make_tree({
        make_file("Ä.txt", "upper"),
        make_file("ä.txt", "lower"),
    });
    const auto bootstrap_result = make_bootstrap(colliding_tree, 0);
    ASSERT_FALSE(bootstrap_result.has_value());
    EXPECT_EQ(bootstrap_result.error().code, ErrorCode::InvalidSnapshot);

    const auto commit_result = make_commit(
        1, {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        colliding_tree);
    ASSERT_FALSE(commit_result.has_value());
    EXPECT_EQ(commit_result.error().code, ErrorCode::InvalidSnapshot);
}

} // namespace
