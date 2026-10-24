// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovotehide.h>

#include <string>

namespace modelnet {

SwarmNotNoVoteHideResult SwarmNoteNotNoVoteHide(const SwarmNotNoVoteHide& note, std::string& err)
{
    SwarmNotNoVoteHideResult result;
    result.hidden = false;
    result.graduated = false;
    // A 51 percent vote does not hide a head and does not graduate a candidate.
    if (note.chain_id.empty()) {
        result.code = "CHAIN";
        result.hidden = false;
        result.graduated = false;
        err = "CHAIN";
        return result;
    }
    if (note.majority) {
        result.code = "VISIBLE";
        result.hidden = false;
        result.graduated = false;
        err = "VISIBLE";
        return result;
    }
    if (note.want_hide) {
        result.code = "HELD";
        result.hidden = false;
        result.graduated = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.hidden = false;
    result.graduated = false;
    err.clear();
    return result;
}

} // namespace modelnet
