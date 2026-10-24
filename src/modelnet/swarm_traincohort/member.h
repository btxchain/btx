// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TRAINCOHORT_MEMBER_H
#define BITCOIN_MODELNET_SWARM_TRAINCOHORT_MEMBER_H

#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One local integer trainer. step 0 and an empty state_hash means untrained.
 * local_step_taken is set only after a committed step whose replay matched.
 */
struct TrainCohortMember {
    std::string id;
    uint64_t step{0};
    std::string state_hash;
    std::string pending_hash;
    bool pending{false};
    bool local_step_taken{false};
    IntegerTrainer trainer;
};

bool AddCohortMember(std::vector<TrainCohortMember>& members, const std::string& id, std::string& err);

TrainCohortMember* FindCohortMember(std::vector<TrainCohortMember>& members, const std::string& id);
const TrainCohortMember* FindCohortMember(const std::vector<TrainCohortMember>& members, const std::string& id);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TRAINCOHORT_MEMBER_H
