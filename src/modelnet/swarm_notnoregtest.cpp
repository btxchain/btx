// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoregtest.h>

namespace modelnet {

SwarmNotNoRegtestResult SwarmNoteNotNoRegtest(const SwarmNotNoRegtest& note, std::string& err)
{
    SwarmNotNoRegtestResult result;
    result.mined = false;
    result.broadcast = false;
    if (note.chain_id.empty()) {
        result.code = "CHAIN";
        err = "CHAIN";
        return result;
    }
    if (note.want_mine) {
        result.code = "NOT_MINED";
        err = "NOT_MINED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
