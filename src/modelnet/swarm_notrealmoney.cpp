// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrealmoney.h>

#include <string>

namespace modelnet {

SwarmNotRealMoneyResult SwarmNoteNotRealMoney(const SwarmNotRealMoney& note, std::string& err)
{
    SwarmNotRealMoneyResult result;
    result.opened = false;
    result.funded = false;
    // Currency stays BTX. This note opens no real-money channel.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.opened = false;
        result.funded = false;
        err = "CHANNEL";
        return result;
    }
    if (note.want_open) {
        result.code = "REAL_MONEY";
        result.opened = false;
        result.funded = false;
        err = "REAL_MONEY";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.funded = false;
    err.clear();
    return result;
}

} // namespace modelnet
