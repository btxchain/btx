// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WEARHOLD_ATOMS_H
#define BITCOIN_MODELNET_SWARM_WEARHOLD_ATOMS_H

#include <cstdint>

namespace modelnet {

/**
 * Charge counters this plane keeps fixed. There is no setter.
 * charged() stays false. atoms_moved() stays 0.
 * Measuring joules and refusing a charge do not change them.
 * No atoms move.
 */
class SwarmWearHoldAtoms {
public:
    bool charged() const;
    int64_t atoms_moved() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WEARHOLD_ATOMS_H
