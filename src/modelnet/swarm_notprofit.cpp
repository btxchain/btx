// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notprofit.h>

#include <string>

namespace modelnet {

SwarmNotProfitResult SwarmNoteNotProfit(const SwarmNotProfit& note, std::string& err)
{
    SwarmNotProfitResult result;
    result.shared = false;
    result.paid = false;
    // Profit-share is refused. Nothing is shared or paid.
    if (note.share_id.empty()) {
        result.code = "SHARE";
        result.shared = false;
        result.paid = false;
        err = "SHARE";
        return result;
    }
    if (note.want_share) {
        result.code = "REFUSED";
        result.shared = false;
        result.paid = false;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.paid = false;
    err.clear();
    return result;
}

} // namespace modelnet
