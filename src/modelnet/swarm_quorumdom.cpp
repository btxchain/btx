// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quorumdom.h>

namespace modelnet {

SwarmQuorumDomResult SwarmNoteQuorumDomain(const SwarmQuorumDom& vote, std::string& err)
{
    // The same trust domain is not a quorum.
    if (vote.vote_id.empty()) {
        err = "VOTE";
        return SwarmQuorumDomResult{"VOTE", false};
    }
    if (vote.evaluators < 2 || vote.domains < 2) {
        err = "RANGE";
        return SwarmQuorumDomResult{"RANGE", false};
    }
    if (vote.same_domain) {
        err = "NOT_QUORUM";
        return SwarmQuorumDomResult{"NOT_QUORUM", false};
    }
    if (vote.want_count) {
        err = "HELD";
        return SwarmQuorumDomResult{"HELD", false};
    }
    err.clear();
    return SwarmQuorumDomResult{"NOTED", false};
}

} // namespace modelnet
