// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno51hide2.h>

#include <string>

namespace modelnet {

SwarmNotNo51Hide2Result SwarmNoteNotNo51Hide2(const SwarmNotNo51Hide2& note, std::string& err)
{
    SwarmNotNo51Hide2Result result;
    result.hidden = false;
    // A 51 percent vote does not hide a head.
    if (note.vote_id.empty()) {
        result.code = "VOTE";
        result.hidden = false;
        err = "VOTE";
        return result;
    }
    if (note.majority) {
        result.code = "NOT_HIDDEN";
        result.hidden = false;
        err = "NOT_HIDDEN";
        return result;
    }
    if (note.want_hide) {
        result.code = "HELD";
        result.hidden = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.hidden = false;
    err.clear();
    return result;
}

} // namespace modelnet
