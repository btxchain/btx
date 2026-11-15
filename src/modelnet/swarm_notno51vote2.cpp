// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno51vote2.h>

#include <string>

namespace modelnet {

SwarmNotNo51Vote2Result SwarmNoteNotNo51Vote2(const SwarmNotNo51Vote2& note, std::string& err)
{
    SwarmNotNo51Vote2Result result;
    result.graduated = false;
    result.hidden = false;
    // A 51 percent vote does not graduate and does not hide a head.
    if (note.vote_id.empty()) {
        result.code = "VOTE";
        result.graduated = false;
        result.hidden = false;
        err = "VOTE";
        return result;
    }
    if (note.majority) {
        result.code = "NOT_GRADUATED";
        result.graduated = false;
        result.hidden = false;
        err = "NOT_GRADUATED";
        return result;
    }
    if (note.want_graduate) {
        result.code = "HELD";
        result.graduated = false;
        result.hidden = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.graduated = false;
    result.hidden = false;
    err.clear();
    return result;
}

} // namespace modelnet
