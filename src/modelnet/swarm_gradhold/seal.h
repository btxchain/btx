// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_SEAL_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_SEAL_H

#include <string>

namespace modelnet {

/**
 * Export refusal for a gradient update.
 * An empty id is UPDATE. Every other id is NOT_EXPORTED.
 * exported() stays false. There is no setter that opens the seal,
 * and this type does not store an id.
 */
class SwarmGradHoldSeal {
public:
    std::string refusal(const std::string& update_id) const;
    bool exported() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_SEAL_H
