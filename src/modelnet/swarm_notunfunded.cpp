// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notunfunded.h>

#include <string>

namespace modelnet {

SwarmNotUnfundedResult SwarmNoteNotUnfunded(const SwarmNotUnfunded& note, std::string& err)
{
    SwarmNotUnfundedResult result;
    result.holds_money = false;
    result.advertised = false;
    // An unfunded pool is not advertised as holding money.
    if (note.pool_id.empty()) {
        result.code = "POOL";
        result.holds_money = false;
        result.advertised = false;
        err = "POOL";
        return result;
    }
    if (!note.funded) {
        result.code = "NOT_HOLDING";
        result.holds_money = false;
        result.advertised = false;
        err = "NOT_HOLDING";
        return result;
    }
    if (note.want_advertise) {
        result.code = "NOT_HOLDING";
        result.holds_money = false;
        result.advertised = false;
        err = "NOT_HOLDING";
        return result;
    }
    result.code = "NOTED";
    result.holds_money = false;
    result.advertised = false;
    err.clear();
    return result;
}

} // namespace modelnet
