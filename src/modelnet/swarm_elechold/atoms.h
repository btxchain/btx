// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ELECHOLD_ATOMS_H
#define BITCOIN_MODELNET_SWARM_ELECHOLD_ATOMS_H

#include <cstdint>

namespace modelnet {

/**
 * Charge counters this plane keeps fixed. There is no setter.
 * charged() stays false. atoms_moved() stays 0.
 * Measuring watt-hours and refusing a charge do not change them.
 * No atoms move.
 */
class SwarmElecHoldAtoms {
public:
    bool charged() const;
    int64_t atoms_moved() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ELECHOLD_ATOMS_H
