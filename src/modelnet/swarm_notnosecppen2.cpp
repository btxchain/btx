// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosecppen2.h>

namespace modelnet {

SwarmNotNoSecpPen2Result SwarmNoteNotNoSecpPen2(const SwarmNotNoSecpPen2& note, std::string& err)
{
    SwarmNotNoSecpPen2Result result;
    result.penalized = false;
    // There is no secp256k1 Lightning penalty.
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.penalized = false;
        err = "CHANNEL";
        return result;
    }
    if (note.secp_penalty) {
        result.code = "NOT_PENALIZED";
        result.penalized = false;
        err = "NOT_PENALIZED";
        return result;
    }
    if (note.want_penalty) {
        result.code = "HELD";
        result.penalized = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.penalized = false;
    err.clear();
    return result;
}

} // namespace modelnet
