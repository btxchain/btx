// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_sandbox/nif_sandbox.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
#endif

BOOST_FIXTURE_TEST_SUITE(nif_sandbox_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(root_path_egress_download_elf_and_child_limit)
{
    modelnet::NifSandbox box;
    std::string err;

    BOOST_CHECK(!box.Bind({}, err));
    BOOST_CHECK_EQUAL(err, "ROOT");

    BOOST_CHECK(box.Bind(m_path_root, err));
    BOOST_CHECK(box.OpenPath(m_path_root, err));
    BOOST_CHECK_EQUAL(box.bytes_read(), static_cast<int64_t>(0));
    BOOST_CHECK(box.opened().empty());

    const fs::path outside = fs::u8path(m_path_root.utf8string() + "-out");
    BOOST_CHECK(!box.OpenPath(outside, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(box.bytes_read(), static_cast<int64_t>(0));
    BOOST_CHECK(box.opened().empty());

    const fs::path escape = fs::u8path(m_path_root.utf8string() + "/..");
    BOOST_CHECK(!box.OpenPath(escape, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(box.bytes_read(), static_cast<int64_t>(0));
    BOOST_CHECK(box.opened().empty());

    const fs::path nested = m_path_root / "nested";
    BOOST_REQUIRE(fs::create_directories(nested));
    const fs::path note = nested / "plain.txt";
    {
        std::ofstream out(note, std::ios::binary | std::ios::trunc);
        BOOST_REQUIRE(out);
        out.write("ok", 2);
        BOOST_REQUIRE(out);
    }
    const std::vector<unsigned char> file_bytes{'o', 'k'};
    BOOST_CHECK(box.OpenPath(note, err));
    BOOST_CHECK(box.opened() == file_bytes);
    BOOST_CHECK_EQUAL(box.bytes_read(), static_cast<int64_t>(2));

    BOOST_CHECK(!box.OpenPath(escape, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK(box.opened() == file_bytes);
    BOOST_CHECK_EQUAL(box.bytes_read(), static_cast<int64_t>(2));

    BOOST_CHECK(!box.Egress("closed", err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK(!box.egress_opened());

    const fs::path download_path = m_path_root / "download.bin";
    BOOST_CHECK(!fs::exists(download_path));
    BOOST_CHECK(!box.Download("closed", err));
    BOOST_CHECK_EQUAL(err, "DOWNLOAD");
    BOOST_CHECK(!fs::exists(download_path));
    BOOST_CHECK_EQUAL(box.startup_downloads(), static_cast<int64_t>(0));

    const std::vector<unsigned char> elf{0x7f, 'E', 'L', 'F', 'x'};
    BOOST_CHECK(!box.LoadCheckpoint(elf, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(box.data().empty());
    BOOST_CHECK(!box.executable());

    std::vector<unsigned char> pickle{'a'};
    const char marker[] = "PYTHON_PICKLE";
    pickle.insert(pickle.end(), marker, marker + sizeof(marker) - 1);
    BOOST_CHECK(!box.LoadCheckpoint(pickle, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(box.data().empty());
    BOOST_CHECK(!box.executable());

    const std::vector<unsigned char> plain{'p', 'l', 'a', 'i', 'n'};
    BOOST_CHECK(box.LoadCheckpoint(plain, err));
    BOOST_CHECK(box.data() == plain);
    BOOST_CHECK(!box.executable());

    BOOST_CHECK(!box.LoadCheckpoint(elf, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK(box.data() == plain);
    BOOST_CHECK(!box.executable());

    BOOST_CHECK_EQUAL(box.child_count(), static_cast<int64_t>(0));
    BOOST_CHECK(box.SpawnChild(err));
    BOOST_CHECK(box.SpawnChild(err));
    BOOST_CHECK(!box.SpawnChild(err));
    BOOST_CHECK_EQUAL(err, "LIMIT");
    BOOST_CHECK_EQUAL(box.child_count(), static_cast<int64_t>(2));

    BOOST_CHECK(!box.launched());
    BOOST_CHECK(!box.gpu());
    BOOST_CHECK(!box.broadcast());
    BOOST_CHECK_EQUAL(box.automatic_spend(), "0");
}

#ifdef _WIN32
BOOST_AUTO_TEST_CASE(reparse_point_under_the_root_is_refused)
{
    const fs::path root = m_path_root / "root";
    const fs::path outside = m_path_root / "outside";
    BOOST_REQUIRE(fs::create_directories(root));
    BOOST_REQUIRE(fs::create_directories(outside));
    {
        std::ofstream out(outside / "secret.txt", std::ios::binary | std::ios::trunc);
        BOOST_REQUIRE(out);
        out.write("no", 2);
        BOOST_REQUIRE(out);
    }

    modelnet::NifSandbox box;
    std::string err;
    BOOST_REQUIRE(box.Bind(root, err));
    BOOST_CHECK(!box.OpenPath(root / ".." / "outside" / "secret.txt", err));
    BOOST_CHECK_EQUAL(err, "DENIED");

    // A drive-qualified name below the root ("<root>\C:x" on drive C:) is
    // refused. Without the root-name check the walk would open "<root>\x".
    {
        std::ofstream out(root / "x", std::ios::binary | std::ios::trunc);
        BOOST_REQUIRE(out);
        out.write("x", 1);
        BOOST_REQUIRE(out);
    }
    const std::string drive{fs::path{fs::absolute(root).root_name()}.utf8string()};
    BOOST_REQUIRE(!drive.empty());
    BOOST_CHECK(!box.OpenPath(fs::u8path(root.utf8string() + "\\" + drive + "x"), err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(box.bytes_read(), static_cast<int64_t>(0));
    BOOST_CHECK(box.opened().empty());

    // A directory symbolic link under the root that points outside it. The test
    // root can mix '/' and '\', so the target is written with '\' only.
    const fs::path link_dir = root / "link";
    fs::path target{outside};
    target.make_preferred();
    if (!CreateSymbolicLinkW(link_dir.wstring().c_str(), target.wstring().c_str(),
                             SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        const DWORD code{GetLastError()};
        BOOST_REQUIRE_MESSAGE(code == ERROR_PRIVILEGE_NOT_HELD, "CreateSymbolicLinkW failed with Windows error " << code);
        BOOST_TEST_MESSAGE("NOT CHECKED: Windows refused to create a symbolic link here (privilege not held), so the "
                           "reparse-point refusal did not run. Run elevated or with developer mode to check it.");
        BOOST_CHECK_EQUAL(box.bytes_read(), static_cast<int64_t>(0));
        return;
    }
    const DWORD attributes{GetFileAttributesW(link_dir.wstring().c_str())};
    BOOST_REQUIRE(attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0);
    BOOST_REQUIRE(fs::exists(link_dir / "secret.txt"));

    BOOST_CHECK(!box.OpenPath(link_dir / "secret.txt", err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK(!box.OpenPath(link_dir, err));
    BOOST_CHECK_EQUAL(err, "DENIED");
    BOOST_CHECK_EQUAL(box.bytes_read(), static_cast<int64_t>(0));
    BOOST_CHECK(box.opened().empty());

    // A bound root that is itself a link does not open.
    modelnet::NifSandbox linked;
    BOOST_REQUIRE(linked.Bind(link_dir, err));
    BOOST_CHECK(!linked.OpenPath(link_dir, err));
    BOOST_CHECK_EQUAL(err, "DENIED");

    // Removes the link only, not its target.
    BOOST_CHECK(RemoveDirectoryW(link_dir.wstring().c_str()));
}
#endif // _WIN32

BOOST_AUTO_TEST_SUITE_END()
