// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESLOTS_RECORD_H
#define BITCOIN_MODELNET_SWARM_NICHESLOTS_RECORD_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One niche's own slots and the tasks spent against those slots.
 * A row is never shared with another niche.
 */
struct SwarmNicheSlotsRecord {
    int64_t remaining{0};
    std::vector<std::string> tasks;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESLOTS_RECORD_H
