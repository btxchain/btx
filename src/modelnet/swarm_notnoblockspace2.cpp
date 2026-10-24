// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoblockspace2.h>

namespace modelnet {

SwarmNotNoBlockSpace2Result SwarmNoteNotNoBlockSpace2(const SwarmNotNoBlockSpace2& note, std::string& err)
{
    SwarmNotNoBlockSpace2Result result;
    // Block spacing stays 90 seconds and is not a wall-clock guarantee.
    result.guaranteed = false;
    result.seconds = 90;
    if (note.chain_id.empty()) {
        result.code = "CHAIN";
        result.guaranteed = false;
        result.seconds = 90;
        err = "CHAIN";
        return result;
    }
    if (note.want_guarantee) {
        result.code = "HELD";
        result.guaranteed = false;
        result.seconds = 90;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.guaranteed = false;
    result.seconds = 90;
    err.clear();
    return result;
}

} // namespace modelnet
