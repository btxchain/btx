// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_CLAIM_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_CLAIM_H

#include <string>

namespace modelnet {

/**
 * Refuse a claim.
 * A covered id and a 32-byte preimage description are still UNQUALIFIED.
 * An unknown id is the same refusal. No atoms move and nothing is broadcast.
 * This function stores nothing and does not mark a claim as having happened.
 */
bool SwarmSigCoverRefuseClaim(bool covered, bool preimage_32, const std::string& id, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_CLAIM_H
