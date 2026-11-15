// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HASHLOCK_OFFER_H
#define BITCOIN_MODELNET_SWARM_HASHLOCK_OFFER_H

#include <modelnet/swarm_hashlock/types.h>

#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-memory hashlock offers. Offer stores one payment hash per id.
 * An empty id is INVOICE. A hash whose size is not 32 is PREIMAGE and
 * is not inserted. A second Offer of the same id is REPLAY and leaves
 * the first hash in place.
 */
class SwarmHashlockOfferBook {
public:
    bool Offer(const std::string& id, const std::vector<unsigned char>& payment_hash, std::string& err);

    /**
     * Unknown id is INVOICE. Otherwise the claim rules in
     * SwarmHashlockApplyClaim apply. A refused claim does not drop the offer.
     */
    bool Claim(const std::string& id, const std::vector<unsigned char>& preimage, std::string& err);

    bool offered(const std::string& id) const;
    bool claimed(const std::string& id) const;

    /** 1 after one successful claim, otherwise 0. A replay does not raise it. */
    int claims(const std::string& id) const;

    /**
     * Copy the first stored payment hash.
     * An unknown id returns false and leaves out unchanged.
     */
    bool stored_hash(const std::string& id, std::vector<unsigned char>& out) const;

private:
    std::map<std::string, SwarmHashlockOffer> m_offers;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HASHLOCK_OFFER_H
