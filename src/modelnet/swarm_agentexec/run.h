// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_RUN_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_RUN_H

#include <modelnet/swarm_agentexec/journal.h>
#include <modelnet/swarm_agentexec/result.h>

#include <string>

namespace modelnet {

/**
 * Hash payload in this process and store the hex.
 * An empty payload is PAYLOAD and does not set ran().
 * A path and payload already stored is REPLAY and keeps the first digest.
 * Otherwise result() becomes HexStr(Hash(payload)) and ran() becomes true.
 */
bool SwarmAgentExecRun(SwarmAgentExecJournal& journal,
                       SwarmAgentExecResult& result,
                       const std::string& path,
                       const std::string& payload,
                       std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_RUN_H
