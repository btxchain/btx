// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EARLYHALT_STOP_H
#define BITCOIN_MODELNET_SWARM_EARLYHALT_STOP_H

#include <modelnet/swarm_earlyhalt/mark.h>
#include <modelnet/swarm_earlyhalt/remain.h>

namespace modelnet {

/**
 * Stops the run after a falling score.
 * The mark is raised and the remainder becomes zero. The seat budget
 * and the stored score are not arguments, so both stay.
 */
class SwarmEarlyHaltStop {
public:
    void Apply(SwarmEarlyHaltRemain& remain, SwarmEarlyHaltMark& mark) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EARLYHALT_STOP_H
