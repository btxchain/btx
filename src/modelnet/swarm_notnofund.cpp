// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofund.h>

#include <string>

namespace modelnet {

SwarmNotNoFundResult SwarmNoteNotNoFund(const SwarmNotNoFund& note, std::string& err)
{
    SwarmNotNoFundResult result;
    result.broadcast = false;
    result.confirmed = false;
    // This note does not reach a funding broadcast or a funding confirmation.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.broadcast = false;
        result.confirmed = false;
        err = "CHANNEL";
        return result;
    }
    if (note.want_broadcast) {
        result.code = "NOT_OPEN";
        result.broadcast = false;
        result.confirmed = false;
        err = "NOT_OPEN";
        return result;
    }
    result.code = "NOTED";
    result.broadcast = false;
    result.confirmed = false;
    err.clear();
    return result;
}

} // namespace modelnet
