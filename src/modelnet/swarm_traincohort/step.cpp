// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_traincohort/step.h>

#include <modelnet/swarm_traincohort/error.h>
#include <modelnet/training_integer.h>

#include <string>
#include <utility>

namespace modelnet {

bool CohortLocalStep(TrainCohortMember& member, std::string& err)
{
    if (member.local_step_taken) {
        err = COHORT_REPLAY;
        return false;
    }

    IntegerTrainer advanced = member.trainer;
    if (!advanced.IntegerTrainer::Step(err)) return false;

    const IntegerState published = advanced.State();
    if (!advanced.IntegerTrainer::ReplayMatches(published, err)) return false;

    member.trainer = std::move(advanced);
    member.step = published.step;
    member.state_hash = published.state_hash;
    member.local_step_taken = true;
    err.clear();
    return true;
}

} // namespace modelnet
