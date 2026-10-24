// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_REORG_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_REORG_H

#include <modelnet/swarm_faultboard/reserve.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Reorg freeze, one shared reservation, and collateral reuse.
 * Reserve after freeze stores nothing. DoubleCollateral does not consult
 * the freeze bit. Both share one reservation slot.
 */
bool SwarmFaultReorg(SwarmFaultReserve& reserve, std::string& err);
bool SwarmFaultDoubleCollateral(SwarmFaultReserve& reserve, int64_t amount, std::string& err);
bool SwarmFaultReserveAmount(SwarmFaultReserve& reserve, int64_t amount, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_REORG_H
