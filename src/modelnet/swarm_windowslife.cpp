// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_windowslife.h>

namespace modelnet {

SwarmWindowsLifeResult SwarmNoteWindowsLife(const SwarmWindowsLife& node, std::string& err)
{
    SwarmWindowsLifeResult result;
    result.passed = false;
    // A missing guest agent does not pass a Windows lifecycle.
    if (node.node_id.empty()) {
        result.code = "NODE";
        result.passed = false;
        err = "NODE";
        return result;
    }
    if (!node.guest_agent) {
        result.code = "NOT_PASSED";
        result.passed = false;
        err = "NOT_PASSED";
        return result;
    }
    if (node.want_pass) {
        result.code = "HELD";
        result.passed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet
