// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_OPEN_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_OPEN_H

#include <modelnet/swarm_disputestay/book.h>

#include <string>

namespace modelnet {

/**
 * Opens one dispute id.
 * An empty id is DISPUTE and the book stays as it was.
 * A new non-empty id is stored and the call returns true.
 * A second Open of the same id is REPLAY and leaves the first dispute.
 * Those checks run in that order. A success clears err.
 * Nothing is settled and no atoms move.
 */
class SwarmDisputeStayOpen {
public:
    bool Apply(SwarmDisputeStayBook& book, const std::string& dispute, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_OPEN_H
