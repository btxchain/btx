// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorealmoney2.h>

namespace modelnet {

SwarmNotNoRealMoney2Result SwarmNoteNotNoRealMoney2(const SwarmNotNoRealMoney2& note, std::string& err)
{
    // No real-money channel is opened.
    SwarmNotNoRealMoney2Result result;
    result.opened = false;
    result.atoms = 0;
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.opened = false;
        result.atoms = 0;
        err = "CHANNEL";
        return result;
    }
    if (note.real_money) {
        result.code = "NOT_OPENED";
        result.opened = false;
        result.atoms = 0;
        err = "NOT_OPENED";
        return result;
    }
    if (note.want_open) {
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
