// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HASHLOCK_CLAIM_H
#define BITCOIN_MODELNET_SWARM_HASHLOCK_CLAIM_H

#include <modelnet/swarm_hashlock/types.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Claim one stored offer.
 * preimage.size() != 32 is PREIMAGE and stores nothing.
 * A digest mismatch is HASHLOCK and does not mark the offer claimed.
 * A match marks claimed once. A second matching preimage is REPLAY.
 * The preimage bytes are not retained.
 */
bool SwarmHashlockApplyClaim(SwarmHashlockOffer& offer,
                             const std::vector<unsigned char>& preimage,
                             std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HASHLOCK_CLAIM_H
