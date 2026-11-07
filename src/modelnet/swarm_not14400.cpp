// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_not14400.h>

namespace modelnet {

SwarmNot14400Result SwarmNoteNot14400(const SwarmNot14400& note, std::string& err)
{
    SwarmNot14400Result result;
    result.guaranteed = false;
    result.seconds = 0;
    if (note.channel_id.empty()) {
        result.code = "CHANNEL";
        result.guaranteed = false;
        result.seconds = 0;
        err = "CHANNEL";
        return result;
    }
    if (note.blocks != 160) {
        result.code = "NOT_GUARANTEE";
        result.guaranteed = false;
        result.seconds = 0;
        err = "NOT_GUARANTEE";
        return result;
    }
    if (note.want_guarantee) {
        result.code = "NOT_GUARANTEE";
        result.guaranteed = false;
        result.seconds = 0;
        err = "NOT_GUARANTEE";
        return result;
    }
    result.code = "NOTED";
    result.guaranteed = false;
    result.seconds = 0;
    err.clear();
    return result;
}

} // namespace modelnet
