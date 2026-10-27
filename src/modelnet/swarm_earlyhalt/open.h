// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_OPEN_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_OPEN_H

#include <modelnet/swarm_earlyhalt/remain.h>
#include <modelnet/swarm_earlyhalt/seat.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Opens the one row.
 * budget < 1 is BUDGET and the seat and remainder stay as they were.
 * A second Open is REPLAY and leaves the first budget.
 */
class SwarmEarlyHaltOpen {
public:
    bool Apply(SwarmEarlyHaltSeat& seat, SwarmEarlyHaltRemain& remain, int64_t budget, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_OPEN_H
