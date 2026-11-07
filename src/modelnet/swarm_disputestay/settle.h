// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_SETTLE_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_SETTLE_H

#include <modelnet/swarm_disputestay/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Refuses to settle a dispute.
 * An empty id is DISPUTE and stores nothing.
 * Any other id is HELD. The call returns false.
 * An unknown id is not stored. Atoms below 1 on a known id add nothing.
 * Atoms at or above 1 are still held and add nothing.
 * The book is taken by const reference, so settled stays false and
 * atoms_moved stays 0.
 */
class SwarmDisputeStaySettle {
public:
    bool Apply(const SwarmDisputeStayBook& book,
               const std::string& dispute,
               int64_t atoms,
               std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_SETTLE_H
