// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_profit.h>

#include <cstdint>

namespace modelnet {

SwarmProfitShareResult SwarmNoteProfitShare(const SwarmProfitShare& share, std::string& err)
{
    SwarmProfitShareResult result;
    result.accepted = false;
    if (share.instrument_id.empty() || share.atoms < 0) {
        result.code = "INSTRUMENT";
        err = "INSTRUMENT";
        return result;
    }
    if (share.profit_share) {
        result.code = "PROFIT_REFUSED";
        err = "PROFIT_REFUSED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
