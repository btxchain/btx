// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_LEDGER_H
#define BITCOIN_MODELNET_SWARM_FORWARD_LEDGER_H

#include <modelnet/swarm_forward/hop.h>

#include <vector>

namespace modelnet {

/**
 * Hops accepted by a successful forward.
 * A refused forward does not call Note, so the ledger stays unchanged.
 */
class SwarmForwardLedger {
public:
    void Note(const SwarmForwardHop& hop);
    std::size_t size() const;
    const std::vector<SwarmForwardHop>& hops() const { return m_hops; }

private:
    std::vector<SwarmForwardHop> m_hops;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_LEDGER_H
