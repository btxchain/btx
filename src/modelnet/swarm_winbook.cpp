// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_winbook.h>

#include <string>

namespace modelnet {

SwarmWinBookResult SwarmRecordWindows(const SwarmWinBook& book, std::string& err)
{
    SwarmWinBookResult result;
    result.passed = false;
    result.started = false;
    // A Windows record can see a running VM and still does not pass the lifecycle.
    if (book.check_id.empty()) {
        result.code = "CHECK";
        result.passed = false;
        result.started = false;
        err = "CHECK";
        return result;
    }
    if (book.passthrough) {
        result.code = "NOT_STARTED";
        result.passed = false;
        result.started = false;
        err = "NOT_STARTED";
        return result;
    }
    if (!book.guest_agent) {
        result.code = "NOT_PASSED";
        result.passed = false;
        result.started = false;
        err = "NOT_PASSED";
        return result;
    }
    if (!book.vm_running) {
        result.code = "ABSENT";
        result.passed = false;
        result.started = false;
        err = "ABSENT";
        return result;
    }
    if (book.want_pass) {
        result.code = "HELD";
        result.passed = false;
        result.started = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.passed = false;
    result.started = false;
    err.clear();
    return result;
}

} // namespace modelnet
