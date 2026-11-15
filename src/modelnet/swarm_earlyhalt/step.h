// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_STEP_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_STEP_H

#include <modelnet/swarm_earlyhalt/mark.h>
#include <modelnet/swarm_earlyhalt/remain.h>
#include <modelnet/swarm_earlyhalt/score.h>
#include <modelnet/swarm_earlyhalt/seat.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Records one score on an open row.
 * Before Open the result is STEP and nothing is stored.
 * A marked run, or a remainder of zero, is STOPPED and stores nothing.
 * A successful step spends one from the remainder and stores the score.
 * A score lower than the previous stored score stops the run. That step
 * still succeeds. The falling score stays on the row.
 */
class SwarmEarlyHaltStep {
public:
    bool Apply(SwarmEarlyHaltSeat& seat, SwarmEarlyHaltRemain& remain, SwarmEarlyHaltScore& score, SwarmEarlyHaltMark& mark, int64_t next, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_STEP_H
