// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WEARCOST_H
#define BITCOIN_MODELNET_SWARM_WEARCOST_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmWearCost {
    std::string meter_id;
    bool measured;
    bool want_charge;
};

struct SwarmWearCostResult {
    std::string code;
    bool charged;
    int64_t atoms;
};

SwarmWearCostResult SwarmNoteWearCost(const SwarmWearCost& meter, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WEARCOST_H
