// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_OFFER_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_OFFER_H

#include <modelnet/swarm_gradhold/book.h>

#include <string>

namespace modelnet {

/**
 * Records one gradient update id.
 * An empty id is UPDATE and the book stays as it was.
 * A new non-empty id is stored and the call returns true.
 * A second Offer of the same id is REPLAY and leaves the first update.
 * Those checks run in that order. A success clears err.
 * Nothing is exported and no bytes move.
 */
class SwarmGradHoldOffer {
public:
    bool Apply(SwarmGradHoldBook& book, const std::string& update_id, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_OFFER_H
