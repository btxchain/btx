// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoregtest2.h>

namespace modelnet {

SwarmNotNoRegtest2Result SwarmNoteNotNoRegtest2(const SwarmNotNoRegtest2& note, std::string& err)
{
    SwarmNotNoRegtest2Result result;
    result.mined = false;
    result.blocks = 0;
    if (note.check_id.empty()) {
        result.code = "CHECK";
        err = "CHECK";
        return result;
    }
    if (note.isolated) {
        result.code = "NOT_MINED";
        err = "NOT_MINED";
        return result;
    }
    if (note.want_mine) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
