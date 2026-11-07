// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STEPWORK_RECORD_H
#define BITCOIN_MODELNET_SWARM_STEPWORK_RECORD_H

#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Store one public experience row from a real integer training step.
 * Admission runs first. On admission, the public kind and outcome_ppm
 * are fixed, then SwarmIntCycle::Run(steps) is called.
 * A failed Run returns the trainer error and does not store.
 * On success, SwarmExperience::Store is called with the id, the public
 * kind, and outcome_ppm equal to steps * 1000. A failed Store returns
 * the store error. The cycle keeps the steps it already took, and the
 * id stays unstored, so a later Record of that id is not a replay.
 * After Store succeeds, Enqueue() lists the id. The reward is not an
 * argument. It is experience.reward(id) from the stored outcome_ppm.
 */
bool SwarmStepWorkRecord(SwarmIntCycle& cycle,
                         SwarmExperience& experience,
                         const std::string& id,
                         int64_t steps,
                         bool is_private,
                         std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STEPWORK_RECORD_H
