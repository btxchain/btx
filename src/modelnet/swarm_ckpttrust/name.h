// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_NAME_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_NAME_H

#include <string>

namespace modelnet {

/**
 * Copies a claim as the recorded label.
 * The claim is an opaque short label. The characters are kept as written.
 * No payload bytes are copied. An empty claim copies nothing.
 */
class SwarmCheckpointTrustName {
public:
    std::string copy(const std::string& claim) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_NAME_H
