// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoexactmine2.h>

namespace modelnet {

SwarmNotNoExactMine2Result SwarmNoteNotNoExactMine2(const SwarmNotNoExactMine2& note, std::string& err)
{
    SwarmNotNoExactMine2Result result;
    result.mined = false;
    result.blocks = 0;
    // An isolated check mines nothing and does not mine past ExactReplay.
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
