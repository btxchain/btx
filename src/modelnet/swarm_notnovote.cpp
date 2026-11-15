// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovote.h>

#include <string>

namespace modelnet {

SwarmNotNoVoteResult SwarmNoteNotNoVote(const SwarmNotNoVote& note, std::string& err)
{
    SwarmNotNoVoteResult result;
    result.graduated = false;
    result.admitted = false;
    if (note.proposal_id.empty()) {
        result.code = "PROPOSAL";
        result.graduated = false;
        result.admitted = false;
        err = "PROPOSAL";
        return result;
    }
    // A 51 percent vote does not graduate a model.
    if (note.vote_ppm >= 510000) {
        result.code = "NOT_GRADUATED";
        result.graduated = false;
        result.admitted = false;
        err = "NOT_GRADUATED";
        return result;
    }
    if (note.want_graduate) {
        result.code = "NOT_GRADUATED";
        result.graduated = false;
        result.admitted = false;
        err = "NOT_GRADUATED";
        return result;
    }
    result.code = "NOTED";
    result.graduated = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
