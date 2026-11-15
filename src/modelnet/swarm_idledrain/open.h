// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_OPEN_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_OPEN_H

#include <modelnet/swarm_idledrain/seat.h>
#include <modelnet/swarm_idledrain/workers.h>

#include <string>

namespace modelnet {

/**
 * First Open records the seat and assigns workers to 1.
 * A second Open is REPLAY and leaves the current count, including a
 * count Admit has raised. This does not look at the drain latch.
 */
class SwarmIdleDrainOpen {
public:
    bool Apply(SwarmIdleDrainSeat& seat, SwarmIdleDrainWorkers& workers, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_OPEN_H
