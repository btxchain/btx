// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_realmoney.h>

namespace modelnet {

SwarmRealMoneyResult SwarmNoteRealMoney(const SwarmRealMoney& channel, std::string& err)
{
    // A real-money channel is not opened.
    SwarmRealMoneyResult result;
    result.opened = false;
    result.atoms = 0;
    if (channel.channel_id.empty()) {
        result.code = "CHANNEL";
        result.opened = false;
        result.atoms = 0;
        err = "CHANNEL";
        return result;
    }
    if (channel.real_money) {
        result.code = "NOT_OPENED";
        result.opened = false;
        result.atoms = 0;
        err = "NOT_OPENED";
        return result;
    }
    if (channel.want_open) {
        result.code = "HELD";
        result.opened = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
