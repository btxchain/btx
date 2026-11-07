// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_DRAIN_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_DRAIN_H

#include <modelnet/swarm_idledrain/mark.h>
#include <modelnet/swarm_idledrain/workers.h>

#include <string>

namespace modelnet {

/**
 * Drains workers to zero for one matching reason.
 * The reason must be exactly battery, thermal, or metered. Any other
 * reason is REASON and changes nothing, including a plane that is
 * already drained. The first matching reason raises the latch and
 * sets workers to 0. A later matching reason, whichever of the three
 * it is, is REPLAY and leaves workers at 0.
 */
class SwarmIdleDrainDrain {
public:
    bool Apply(SwarmIdleDrainMark& mark, SwarmIdleDrainWorkers& workers, const std::string& reason, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_DRAIN_H
