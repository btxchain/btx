// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_PREFIX_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_PREFIX_H

#include <string>

namespace modelnet {

/**
 * Bytewise prefix.
 * prefix matches path when path is at least as long as prefix and the leading
 * bytes are equal. "models/" matches "models/" and "models/a".
 * "models/" does not match "models". An empty prefix matches nothing.
 * Nothing is normalized and no separator is inserted.
 */
bool SwarmAgentExecBeginsWith(const std::string& prefix, const std::string& path);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_PREFIX_H
