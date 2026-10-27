// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stepwork/admit.h>

#include <modelnet/swarm_experience/error.h>
#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_stepwork/codes.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace modelnet {

static_assert(std::string_view{kSwarmStepWorkPrivateData} == kExperiencePrivateData,
              "private refusal");
static_assert(std::string_view{kSwarmStepWorkSteps} == SWARM_INTCYCLE_STEPS, "step refusal");
static_assert(std::string_view{kSwarmStepWorkReplay} == kExperienceReplay, "replay refusal");
static_assert(std::string_view{kSwarmStepWorkEngineAbsent} == SWARM_INTCYCLE_ENGINE_ABSENT,
              "gpu refusal");
static_assert(std::string_view{kSwarmStepWorkWork} != kExperienceTrajectory, "empty id is WORK");

bool SwarmStepWorkAdmitRecord(const SwarmExperience& experience,
                              const std::string& id,
                              int64_t steps,
                              bool is_private,
                              std::string& err)
{
    if (id.empty()) {
        err = kSwarmStepWorkWork;
        return false;
    }
    if (is_private) {
        err = kSwarmStepWorkPrivateData;
        return false;
    }
    if (steps < 1) {
        err = kSwarmStepWorkSteps;
        return false;
    }
    // reward is computed from the stored outcome. -1 means the id is absent.
    if (experience.reward(id) >= 0) {
        err = kSwarmStepWorkReplay;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
