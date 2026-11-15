// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STEPWORK_OUTCOME_H
#define BITCOIN_MODELNET_SWARM_STEPWORK_OUTCOME_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * outcome_ppm for a record is steps * 1000.
 * steps below 1 is STEPS.
 * A product that does not fit in int64_t is RANGE and outcome_ppm stays 0.
 * A product that fits is returned even when the experience store will
 * later refuse it. The store, not this function, decides that range.
 */
bool SwarmStepWorkOutcomePpm(int64_t steps, int64_t& outcome_ppm, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STEPWORK_OUTCOME_H
