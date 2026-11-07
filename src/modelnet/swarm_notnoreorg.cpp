// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreorg.h>

namespace modelnet {

SwarmNotNoReorgResult SwarmNoteNotNoReorg(const SwarmNotNoReorg& note, std::string& err)
{
    SwarmNotNoReorgResult result;
    result.reorged = false;
    result.mined = false;
    if (note.chain_id.empty()) {
        result.code = "CHAIN";
        result.reorged = false;
        result.mined = false;
        err = "CHAIN";
        return result;
    }
    // A note does not reorg or mine past ExactReplay.
    if (note.want_reorg) {
        result.code = "NOT_MINED";
        result.reorged = false;
        result.mined = false;
        err = "NOT_MINED";
        return result;
    }
    result.code = "NOTED";
    result.reorged = false;
    result.mined = false;
    err.clear();
    return result;
}

} // namespace modelnet
