// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_ATOMS_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_ATOMS_H

#include <cstdint>

namespace modelnet {

/**
 * Atom total a Settle would leave on one dispute.
 * Atoms below 1 add nothing: the total stays have.
 * Atoms at or above 1 are still not applied. A dispute cannot be settled,
 * so the total stays have in that case as well.
 */
class SwarmDisputeStayAtoms {
public:
    int64_t after(int64_t have, int64_t atoms) const;
    int64_t moved() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_ATOMS_H
