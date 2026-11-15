// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_DIGEST_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_DIGEST_H

#include <string>

namespace modelnet {

/**
 * In-process digest of payload.
 * The bytes are HexStr(Hash(payload)). Hash runs in this process.
 * The caller refuses an empty payload before this is used.
 */
std::string SwarmAgentExecDigest(const std::string& payload);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_DIGEST_H
