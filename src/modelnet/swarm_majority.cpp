// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_majority.h>

#include <cstdint>

namespace modelnet {

SwarmMajorityResult SwarmNoteMajority(const SwarmMajorityVote& vote, std::string& err)
{
    SwarmMajorityResult result;
    result.graduated = false;
    if (vote.candidate_id.empty() || vote.yes_ppm < 0 || vote.yes_ppm > 1000000) {
        result.code = "VOTE";
        err = "VOTE";
        return result;
    }
    // Graduation is refused even at a majority (510000) or a unanimous
    // share (1000000). A majority vote does not graduate a candidate.
    if (vote.want_graduate) {
        result.code = "GRADUATE_REFUSED";
        result.graduated = false;
        err = "GRADUATE_REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.graduated = false;
    err.clear();
    return result;
}

} // namespace modelnet
