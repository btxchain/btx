// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_EGRESS_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_EGRESS_H

#include <string>

namespace modelnet {

/**
 * Refuses to export a gradient update.
 * An empty id is UPDATE. Any other id is NOT_EXPORTED.
 * The call returns false. It has no book, so it cannot store an
 * unknown id and cannot mark a known id exported.
 */
class SwarmGradHoldEgress {
public:
    bool Apply(const std::string& update_id, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_EGRESS_H
