// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/system.h>

#include <logging.h>
#include <util/fs.h>
#include <util/string.h>
#include <util/time.h>

#ifndef WIN32
#include <sys/stat.h>
#else
#include <compat/compat.h>
#include <codecvt>
#endif

#ifdef HAVE_MALLOPT_ARENA_MAX
#include <malloc.h>
#endif

#include <cstdlib>
#include <locale>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

using util::ReplaceAll;

// Application startup time (used for uptime calculation)
const int64_t nStartupTime = GetTime();

#ifndef WIN32
std::string ShellEscape(const std::string& arg)
{
    std::string escaped = arg;
    ReplaceAll(escaped, "'", "'\"'\"'");
    return "'" + escaped + "'";
}
#endif

#if HAVE_SYSTEM
void runCommand(const std::string& strCommand)
{
    if (strCommand.empty()) return;
#ifndef WIN32
    int nErr = ::system(strCommand.c_str());
#else
    int nErr = ::_wsystem(std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>,wchar_t>().from_bytes(strCommand).c_str());
#endif
    if (nErr)
        LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}
#endif

void SetupEnvironment()
{
#ifdef HAVE_MALLOPT_ARENA_MAX
    // glibc-specific: On 32-bit systems set the number of arenas to 1.
    // By default, since glibc 2.10, the C library will create up to two heap
    // arenas per core. This is known to cause excessive virtual address space
    // usage in our usage. Work around it by setting the maximum number of
    // arenas to 1.
    if (sizeof(void*) == 4) {
        mallopt(M_ARENA_MAX, 1);
    }
#endif
    // On most POSIX systems (e.g. Linux, but not BSD) the environment's locale
    // may be invalid, in which case the "C.UTF-8" locale is used as fallback.
#if !defined(WIN32) && !defined(__APPLE__) && !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__)
    try {
        std::locale(""); // Raises a runtime error if current locale is invalid
    } catch (const std::runtime_error&) {
        setenv("LC_ALL", "C.UTF-8", 1);
    }
#elif defined(WIN32)
    // Set the default input/output charset is utf-8
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
#endif

#ifndef WIN32
    constexpr mode_t private_umask = 0077;
    umask(private_umask);
#endif
}

bool SetupNetworking()
{
#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR || LOBYTE(wsadata.wVersion ) != 2 || HIBYTE(wsadata.wVersion) != 2)
        return false;
#endif
    return true;
}

int GetNumCores()
{
    return std::thread::hardware_concurrency();
}

bool IsLegacyBinaryInvocation(std::string_view argv0, std::string_view legacy_binary)
{
    if (argv0.empty() || legacy_binary.empty()) return false;

    std::string program_name{argv0};
    program_name = fs::PathToString(fs::PathFromString(program_name).filename());
#ifdef WIN32
    constexpr std::string_view exe_ext{".exe"};
    if (program_name.size() > exe_ext.size() &&
        program_name.substr(program_name.size() - exe_ext.size()) == exe_ext) {
        program_name.resize(program_name.size() - exe_ext.size());
    }
#endif
    return program_name == legacy_binary;
}

void WarnAboutLegacyBinaryInvocation(std::string_view argv0, std::string_view legacy_binary, std::string_view canonical_binary)
{
    if (!IsLegacyBinaryInvocation(argv0, legacy_binary)) return;
    std::cerr << "Warning: '" << legacy_binary
              << "' is deprecated and will be removed in a future release. Use '"
              << canonical_binary << "' instead.\n";
}

// Obtain the application startup time (used for uptime calculation)
int64_t GetStartupTime()
{
    return nStartupTime;
}
