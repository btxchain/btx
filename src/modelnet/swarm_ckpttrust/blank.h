// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_BLANK_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_BLANK_H

#include <string>

namespace modelnet {

/**
 * Accepts a claim that can be recorded.
 * A claim is an opaque short label. An empty claim is CLAIM.
 * The caller stores nothing on that result.
 */
class SwarmCheckpointTrustBlank {
public:
    bool accept(const std::string& claim, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_BLANK_H
