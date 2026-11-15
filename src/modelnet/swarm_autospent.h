// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AUTOSPENT_H
#define BITCOIN_MODELNET_SWARM_AUTOSPENT_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmAutoSpent {
    std::string spend_id;
    bool want_set;
};

struct SwarmAutoSpentResult {
    std::string code;
    bool armed;
    int64_t atoms;
};

SwarmAutoSpentResult SwarmKeepAutoSpend(const SwarmAutoSpent& spend, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AUTOSPENT_H
