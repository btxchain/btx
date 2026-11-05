// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_UTIL_PROCESS_H
#define BITCOIN_TEST_UTIL_PROCESS_H

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace test {

inline auto ProcessId()
{
#ifdef _WIN32
    return ::_getpid();
#else
    return ::getpid();
#endif
}

} // namespace test

#endif // BITCOIN_TEST_UTIL_PROCESS_H
