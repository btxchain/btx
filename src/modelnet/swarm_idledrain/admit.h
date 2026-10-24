// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_ADMIT_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_ADMIT_H

#include <modelnet/swarm_idledrain/mark.h>
#include <modelnet/swarm_idledrain/workers.h>

#include <string>

namespace modelnet {

/**
 * Adds one worker before any drain, up to the cap.
 * A raised drain latch is DRAINED and adds nothing, so the zero a
 * drain stored stays zero. A count that would pass 64 is CAPPED and
 * adds nothing. Open is not required.
 */
class SwarmIdleDrainAdmit {
public:
    bool Apply(const SwarmIdleDrainMark& mark, SwarmIdleDrainWorkers& workers, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_ADMIT_H
