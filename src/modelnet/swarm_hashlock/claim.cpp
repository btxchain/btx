// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashlock/claim.h>

#include <modelnet/swarm_hashlock/bind.h>
#include <modelnet/swarm_hashlock/digest.h>

namespace modelnet {

bool SwarmHashlockApplyClaim(SwarmHashlockOffer& offer,
                             const std::vector<unsigned char>& preimage,
                             std::string& err)
{
    if (preimage.size() != kSwarmHashlockDigestSize) {
        err = SWARM_HASHLOCK_PREIMAGE;
        return false;
    }
    const bool digest_ok = SwarmHashlockDigestEquals(offer.payment_hash, preimage);
    const bool bind_ok = SwarmHashlockBindAgrees(offer.id, offer.payment_hash, preimage);
    if (!digest_ok || !bind_ok) {
        err = SWARM_HASHLOCK_HASHLOCK;
        return false;
    }
    if (offer.claimed) {
        err = SWARM_HASHLOCK_REPLAY;
        return false;
    }
    offer.claimed = true;
    err.clear();
    return true;
}

} // namespace modelnet
