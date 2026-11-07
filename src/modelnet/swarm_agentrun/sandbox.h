// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_SANDBOX_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_SANDBOX_H

#include <string>

namespace modelnet {

class SwarmAgentRunTrace;

/**
 * Refuse a run because the sandbox is absent.
 * Always returns false, sets SANDBOX_ABSENT, and appends that name to the
 * trace. Does not start a process, open a socket, or set launched.
 */
bool SwarmAgentRunSandboxRefuse(SwarmAgentRunTrace& trace, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_SANDBOX_H
