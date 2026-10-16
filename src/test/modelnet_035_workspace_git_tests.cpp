// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/workspace_git.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_workspace_git_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Bytes(const std::string& text)
{
    return std::vector<unsigned char>(text.begin(), text.end());
}

std::string ReadFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

bool TreeContains(const fs::path& root, const std::string& needle)
{
    if (!fs::exists(root)) return false;
    for (const auto& ent : fs::recursive_directory_iterator(root)) {
        const fs::path cur{ent.path()};
        if (cur.utf8string().find(needle) != std::string::npos) return true;
        if (!ent.is_regular_file()) continue;
        if (ReadFile(cur).find(needle) != std::string::npos) return true;
    }
    return false;
}

struct TempTree {
    explicit TempTree(fs::path path_in) : path(std::move(path_in)) {}
    ~TempTree()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    fs::path path;
};

} // namespace

BOOST_AUTO_TEST_CASE(workspace_git_writes_current_generation_and_omits_private_note)
{
    TempTree tmp{m_path_root / "workspace-git"};
    const fs::path outside = tmp.path.parent_path() / "outside.txt";
    std::error_code ec;
    fs::remove(outside, ec);

    modelnet::WorkspaceGit workspace(tmp.path);
    std::string err;
    BOOST_CHECK_EQUAL(workspace.Generation("alpha"), uint64_t{0});
    BOOST_CHECK(!workspace.Create("", err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");
    BOOST_CHECK(!workspace.Create("..", err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");

    BOOST_REQUIRE(workspace.Create("alpha", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(fs::is_directory(tmp.path / "alpha"));
    BOOST_CHECK_EQUAL(workspace.Generation("alpha"), uint64_t{1});
    BOOST_CHECK(!workspace.Create("alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");

    const std::string secret = "PRIVNOTE-7f3a9c-do-not-export";
    const std::vector<unsigned char> stale = Bytes("stale");
    BOOST_CHECK(!workspace.Write("missing", 1, "a.txt", stale, err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");
    BOOST_CHECK(!workspace.Write("alpha", 0, "dir/nope.txt", stale, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GENERATION");
    BOOST_CHECK(!fs::exists(tmp.path / "alpha" / "dir" / "nope.txt"));
    BOOST_CHECK(!workspace.Write("alpha", 2, "dir/nope.txt", stale, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GENERATION");
    BOOST_CHECK(!fs::exists(tmp.path / "alpha" / "dir" / "nope.txt"));
    BOOST_CHECK(!workspace.Write("alpha", 1, "../outside.txt", stale, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK(!fs::exists(outside));

    const std::vector<unsigned char> body = Bytes("public-body");
    BOOST_REQUIRE(workspace.Write("alpha", 1, "dir/a.txt", body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(ReadFile(tmp.path / "alpha" / "dir" / "a.txt"), "public-body");
    BOOST_REQUIRE(workspace.NotePrivate("alpha", secret, err));
    BOOST_REQUIRE(workspace.NotePrivate("alpha", "dir/secret.txt", err));

    const std::vector<std::string> files = workspace.ExportFiles("alpha");
    BOOST_REQUIRE_EQUAL(files.size(), 1u);
    BOOST_CHECK_EQUAL(files[0], "dir/a.txt");
    const std::string exported = workspace.ExportPublic("alpha");
    BOOST_CHECK(exported.find(secret) == std::string::npos);
    BOOST_CHECK(exported.find("dir/secret.txt") == std::string::npos);
    BOOST_CHECK(exported.find("file dir/a.txt ") != std::string::npos);
    BOOST_CHECK(!TreeContains(tmp.path, secret));
    BOOST_CHECK(!fs::exists(tmp.path / "alpha" / "dir" / "secret.txt"));

    BOOST_CHECK(!workspace.Publish("alpha", 0, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GENERATION");
    BOOST_CHECK_EQUAL(workspace.Generation("alpha"), uint64_t{1});
    BOOST_REQUIRE(workspace.Publish("alpha", 1, err));
    BOOST_CHECK_EQUAL(workspace.Generation("alpha"), uint64_t{2});

    BOOST_CHECK(!workspace.Write("alpha", 1, "dir/a.txt", Bytes("replaced"), err));
    BOOST_CHECK_EQUAL(err, "BTX035_GENERATION");
    BOOST_CHECK_EQUAL(ReadFile(tmp.path / "alpha" / "dir" / "a.txt"), "public-body");

    BOOST_REQUIRE(workspace.Write("alpha", 2, "dir/a.txt", Bytes("next"), err));
    BOOST_CHECK_EQUAL(ReadFile(tmp.path / "alpha" / "dir" / "a.txt"), "next");
    BOOST_CHECK_EQUAL(workspace.ExportFiles("alpha").size(), 1u);
    BOOST_CHECK(workspace.ExportPublic("alpha").find(secret) == std::string::npos);

    BOOST_CHECK(!fs::exists(outside));
    fs::remove(outside, ec);
}

BOOST_AUTO_TEST_SUITE_END()
