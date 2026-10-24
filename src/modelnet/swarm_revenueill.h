// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REVENUEILL_H
#define BTX_MODELNET_SWARM_REVENUEILL_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmRevenueIll {
    std::string ledger_id;
    bool want_pay;
};

struct SwarmRevenueIllResult {
    std::string code;
    bool paid;
    int64_t atoms;
    int64_t illustrated_a;
    int64_t illustrated_b;
    int64_t illustrated_c;
};

SwarmRevenueIllResult SwarmNoteRevenue(const SwarmRevenueIll& ledger, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REVENUEILL_H
