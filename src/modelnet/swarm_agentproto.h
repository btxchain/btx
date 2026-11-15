// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTPROTO_H
#define BTX_MODELNET_SWARM_AGENTPROTO_H

#include <string>

namespace modelnet {

/**
 * An interoperable MCP or A2A agent message. Receiving a message is not
 * permission to run it. This gate does not require a proprietary framework,
 * does not execute received code, and does not launch a process.
 */
struct SwarmAgentMessage {
    std::string protocol; // "mcp" or "a2a"
    std::string method;
    bool carries_executable{false};
    bool proprietary_framework_required{false};
};

/** Admission of an agent message. executed and launched stay false. */
struct SwarmAgentAdmit {
    bool admitted{false};
    bool executed{false};
    bool launched{false};
    std::string code;
};

/**
 * Order: an empty protocol or method is PROTOCOL. A protocol other than
 * exactly "mcp" or "a2a" is PROTOCOL. A message that carries an executable
 * is CODE_REFUSED. A message that requires a proprietary framework is
 * FRAMEWORK. Otherwise the message is admitted with OK and err is clear.
 * executed and launched stay false. Receiving a message is not permission
 * to run it.
 */
SwarmAgentAdmit SwarmAdmitAgentMessage(const SwarmAgentMessage& message, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTPROTO_H
