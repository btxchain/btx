// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentproto.h>

namespace modelnet {

SwarmAgentAdmit SwarmAdmitAgentMessage(const SwarmAgentMessage& message, std::string& err)
{
    SwarmAgentAdmit result;
    result.executed = false;
    result.launched = false;
    if (message.protocol.empty() || message.method.empty()) {
        result.admitted = false;
        result.code = "PROTOCOL";
        err = "PROTOCOL";
        return result;
    }
    if (message.protocol != "mcp" && message.protocol != "a2a") {
        result.admitted = false;
        result.code = "PROTOCOL";
        err = "PROTOCOL";
        return result;
    }
    if (message.carries_executable) {
        result.admitted = false;
        result.code = "CODE_REFUSED";
        err = "CODE_REFUSED";
        return result;
    }
    if (message.proprietary_framework_required) {
        result.admitted = false;
        result.code = "FRAMEWORK";
        err = "FRAMEWORK";
        return result;
    }
    result.admitted = true;
    result.code = "OK";
    err.clear();
    return result;
}

} // namespace modelnet
