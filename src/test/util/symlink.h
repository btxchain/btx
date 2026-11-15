// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_UTIL_SYMLINK_H
#define BITCOIN_TEST_UTIL_SYMLINK_H

#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#ifdef WIN32
#include <windows.h>
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
#endif

/**
 * Create a symbolic link at `link` that points to `target`.
 *
 * MinGW's libstdc++ does not implement std::filesystem::create_symlink, so on
 * Windows this calls CreateSymbolicLinkW, with the directory flag when
 * `directory` is set. If Windows refuses the link for lack of privilege (no
 * developer mode, not elevated), it logs "Symbolic links absent here", the
 * wording of the other skip messages in the unit tests, and returns false, and
 * the caller skips the checks that need the link. Any other error fails the
 * test.
 */
inline bool CreateTestSymlink(const fs::path& target, const fs::path& link, [[maybe_unused]] bool directory)
{
#ifdef WIN32
    // The test root can mix '/' and '\', so the target is written with '\' only.
    fs::path native{target};
    native.make_preferred();
    DWORD flags{SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE};
    if (directory) flags |= SYMBOLIC_LINK_FLAG_DIRECTORY;
    if (CreateSymbolicLinkW(link.wstring().c_str(), native.wstring().c_str(), flags)) return true;
    const DWORD code{GetLastError()};
    BOOST_REQUIRE_MESSAGE(code == ERROR_PRIVILEGE_NOT_HELD, "CreateSymbolicLinkW failed with Windows error " << code);
    BOOST_TEST_MESSAGE("Symbolic links absent here: Windows refused CreateSymbolicLinkW (privilege not held), so "
                       "the link refusal did not run. Run elevated or with developer mode to check it.");
    return false;
#else
    fs::create_symlink(target, link);
    return true;
#endif
}

/**
 * Whether `path` itself is a symbolic link. MinGW's symlink_status() never
 * reports a link, so on Windows this reads the reparse attribute.
 */
inline bool IsTestSymlink(const fs::path& path)
{
#ifdef WIN32
    const DWORD attributes{GetFileAttributesW(path.wstring().c_str())};
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    return fs::is_symlink(fs::symlink_status(path));
#endif
}

#endif // BITCOIN_TEST_UTIL_SYMLINK_H
