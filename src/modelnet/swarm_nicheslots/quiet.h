// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESLOTS_QUIET_H
#define BITCOIN_MODELNET_SWARM_NICHESLOTS_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * Status this plane cannot change.
 * No bytes move and nothing is broadcast. Slot accounting is local
 * bookkeeping; it does not spend real atoms.
 */
class SwarmNicheSlotsQuiet {
public:
    uint64_t bytes_moved() const;
    bool broadcast() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESLOTS_QUIET_H
