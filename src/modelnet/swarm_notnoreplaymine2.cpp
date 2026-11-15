// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreplaymine2.h>

namespace modelnet {

SwarmNotNoReplayMine2Result SwarmNoteNotNoReplayMine2(const SwarmNotNoReplayMine2& note, std::string& err)
{
    SwarmNotNoReplayMine2Result result;
    result.mined = false;
    result.blocks = 0;
    // An isolated check mines nothing past ExactReplay.
    if (note.check_id.empty()) {
        result.code = "CHECK";
        result.mined = false;
        result.blocks = 0;
        err = "CHECK";
        return result;
    }
    if (note.want_mine) {
        result.code = "HELD";
        result.mined = false;
        result.blocks = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.mined = false;
    result.blocks = 0;
    err.clear();
    return result;
}

} // namespace modelnet
