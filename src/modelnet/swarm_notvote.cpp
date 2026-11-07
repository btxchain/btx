// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notvote.h>

#include <string>

namespace modelnet {

SwarmNotVoteResult SwarmNoteNotVote(const SwarmNotVote& note, std::string& err)
{
    SwarmNotVoteResult result;
    result.graduated = false;
    result.realm_promoted = false;
    if (note.vote_id.empty()) {
        result.code = "VOTE";
        result.graduated = false;
        result.realm_promoted = false;
        err = "VOTE";
        return result;
    }
    // A 51 percent vote does not graduate a model and does not admit ExactReplay.
    if (note.want_graduate) {
        result.code = "NOT_GRADUATED";
        result.graduated = false;
        result.realm_promoted = false;
        err = "NOT_GRADUATED";
        return result;
    }
    result.code = "NOTED";
    result.graduated = false;
    result.realm_promoted = false;
    err.clear();
    return result;
}

} // namespace modelnet
