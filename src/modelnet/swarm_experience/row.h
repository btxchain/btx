// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXPERIENCE_ROW_H
#define BITCOIN_MODELNET_SWARM_EXPERIENCE_ROW_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One stored trajectory. Reward is not a field: it is computed from
 * outcome_ppm. offered becomes true only after TrainFrom accepts the id.
 */
struct ExperienceRow {
    std::string id;
    std::string kind;
    int64_t outcome_ppm{0};
    bool offered{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXPERIENCE_ROW_H
