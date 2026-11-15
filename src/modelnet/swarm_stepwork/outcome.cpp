// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stepwork/outcome.h>

#include <modelnet/swarm_experience/error.h>
#include <modelnet/swarm_experience/limits.h>
#include <modelnet/swarm_stepwork/codes.h>

#include <cstdint>
#include <limits>
#include <string>

namespace modelnet {

static_assert(500 * kSwarmStepWorkPpmPerStep == kExperienceRewardThresholdPpm,
              "500 steps meets the reward threshold");
static_assert(1000 * kSwarmStepWorkPpmPerStep == kExperiencePpmMax,
              "1000 steps is the top stored ppm");

bool SwarmStepWorkOutcomePpm(int64_t steps, int64_t& outcome_ppm, std::string& err)
{
    outcome_ppm = 0;
    if (steps < 1) {
        err = kSwarmStepWorkSteps;
        return false;
    }
    if (steps > std::numeric_limits<int64_t>::max() / kSwarmStepWorkPpmPerStep) {
        err = kExperienceRange;
        return false;
    }
    outcome_ppm = steps * kSwarmStepWorkPpmPerStep;
    err.clear();
    return true;
}

} // namespace modelnet
