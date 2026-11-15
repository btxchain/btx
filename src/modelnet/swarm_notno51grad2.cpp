// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notno51grad2.h>

#include <string>

namespace modelnet {

SwarmNotNo51Grad2Result SwarmNoteNotNo51Grad2(const SwarmNotNo51Grad2& note, std::string& err)
{
    SwarmNotNo51Grad2Result result;
    result.graduated = false;
    // A 51 percent vote does not graduate a model.
    if (note.vote_id.empty()) {
        result.code = "VOTE";
        result.graduated = false;
        err = "VOTE";
        return result;
    }
    if (note.majority) {
        result.code = "NOT_GRADUATED";
        result.graduated = false;
        err = "NOT_GRADUATED";
        return result;
    }
    if (note.want_graduate) {
        result.code = "HELD";
        result.graduated = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.graduated = false;
    err.clear();
    return result;
}

} // namespace modelnet
