// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROFITSHARE_H
#define BITCOIN_MODELNET_SWARM_PROFITSHARE_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmProfitShareRequest {
    std::string share_id;
    bool want_share;
};

struct SwarmProfitShareRefusal {
    std::string code;
    bool shared;
    int64_t atoms;
};

SwarmProfitShareRefusal SwarmRefuseProfitShare(const SwarmProfitShareRequest& share, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROFITSHARE_H
