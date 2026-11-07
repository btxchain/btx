// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REMEDY_OPEN_H
#define BITCOIN_MODELNET_SWARM_REMEDY_OPEN_H

#include <modelnet/swarm_paymesh.h>

#include <string>

namespace modelnet {

/**
 * First revocation for one plane.
 * sequence below 1 is SEQUENCE and produces no revocation.
 * A created revocation comes from SwarmNewRevocation and stays unreleased.
 */
class SwarmRemedyOpen {
public:
    bool Create(int sequence, unsigned char fill, SwarmRevocation& out, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REMEDY_OPEN_H
