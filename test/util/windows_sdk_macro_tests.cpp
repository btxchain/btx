// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Standalone native Windows compile/run regression, from an x64 VS shell:
// cl /nologo /std:c++20 /EHsc /DWIN32 /DWIN32_LEAN_AND_MEAN /DNOMINMAX ^
//    /I src test/util/windows_sdk_macro_tests.cpp /link Ws2_32.lib
// Repeat with /DBTX_SDK_FIRST to check the reverse include order.

#ifdef BTX_SDK_FIRST
#include <winsock2.h>
#include <shellapi.h>
#include <shlobj.h>
#include <iphlpapi.h>
#endif

#include <compat/compat.h>

// These headers are deliberately read after BTX's macro cleanup.
#include <shellapi.h>
#include <shlobj.h>
#include <iphlpapi.h>

#include <type_traits>

#if defined(near) || defined(far)
#error Lowercase Windows macros must not replace BTX identifiers
#endif

#define BTX_STRINGIFY_INNER(x) #x
#define BTX_STRINGIFY(x) BTX_STRINGIFY_INNER(x)
static_assert(sizeof(BTX_STRINGIFY(FAR)) == 1);
static_assert(sizeof(BTX_STRINGIFY(NEAR)) == 1);
static_assert(std::is_same_v<int FAR*, int*>);
static_assert(std::is_same_v<int NEAR*, int*>);

int main()
{
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
    fd_set descriptors;
    FD_ZERO(&descriptors);
    const SOCKET descriptor{7}; // FD-set bookkeeping only; no socket is opened.
    FD_SET(descriptor, &descriptors);
    const bool present{FD_ISSET(descriptor, &descriptors) != 0};
    FD_CLR(descriptor, &descriptors);
    const bool absent{FD_ISSET(descriptor, &descriptors) == 0};
    WSACleanup();
    const int near{1};
    const int far{2};
    return present && absent && near + far == 3 ? 0 : 1;
}
