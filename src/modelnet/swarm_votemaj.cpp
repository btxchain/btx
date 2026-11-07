// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_votemaj.h>

namespace modelnet {

// A majority vote does not graduate a model and does not hide a head.
SwarmVoteMajResult SwarmNoteMajority(const SwarmVoteMaj& vote, std::string& err)
{
    SwarmVoteMajResult out;
    out.graduated = false;
    out.hidden = false;
    if (vote.vote_id.empty()) {
        out.code = "VOTE";
        err = "VOTE";
        return out;
    }
    if (vote.majority) {
        out.code = "NOT_GRADUATED";
        err = "NOT_GRADUATED";
        return out;
    }
    if (vote.want_graduate || vote.want_hide) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
