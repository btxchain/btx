// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_STAY_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_STAY_H

#include <string>

namespace modelnet {

/**
 * The stored claim stays untrusted.
 * refusal() is NOT_TRUST. trusted() stays false.
 * A checkpoint-only claim is not lineage authority.
 * This type does not store a claim and does not move bytes.
 */
class SwarmCheckpointTrustStay {
public:
    std::string refusal() const;
    bool trusted() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_STAY_H
