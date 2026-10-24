// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_PRIVATE_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_PRIVATE_H

#include <string>

namespace modelnet {

/**
 * True when path begins with the bytes "private/".
 * A stored Allow of that prefix does not make the path executable.
 * "private" and "privateer/a" do not begin with those bytes.
 */
bool SwarmAgentExecPrivatePath(const std::string& path);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_PRIVATE_H
