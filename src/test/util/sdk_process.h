// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_UTIL_SDK_PROCESS_H
#define BITCOIN_TEST_UTIL_SDK_PROCESS_H

#include <string>
#include <vector>

namespace sdk_test {
/** Run the SDK interpreter and script as literal arguments, without a shell.
 * Return its exit code, or -1 when launch/communication fails.
 * Both streams are drained; append stderr only for diagnostic callers.
 */
int Spawn(const std::vector<std::string>& argv, std::string& output, bool include_stderr = true);
std::string Which(const char* name);
/** Locate and verify Python 3. SDK Python parity remains mandatory. */
std::string Python3();
} // namespace sdk_test

#endif // BITCOIN_TEST_UTIL_SDK_PROCESS_H
