// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_norealmoney.h>

namespace modelnet {

SwarmNoRealMoneyResult SwarmNoteNoRealMoney(const SwarmNoRealMoney& note, std::string& err)
{
    SwarmNoRealMoneyResult result;
    result.opened = false;
    result.broadcast = false;
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.opened = false;
        result.broadcast = false;
        err = "CHANNEL";
        return result;
    }
    // There are no real-money channels.
    if (note.want_real_money) {
        result.code = "REAL_MONEY";
        result.opened = false;
        result.broadcast = false;
        err = "REAL_MONEY";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
