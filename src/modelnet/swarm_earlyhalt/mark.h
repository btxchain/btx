// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_MARK_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_MARK_H

namespace modelnet {

/**
 * Early-stop mark for the one row.
 * raise sets it. Nothing in this type clears it. Promote of a marked
 * row refuses and leaves the mark, the score, and the budget.
 */
class SwarmEarlyHaltMark {
public:
    bool set() const { return m_set; }
    void raise();

private:
    bool m_set{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_MARK_H
