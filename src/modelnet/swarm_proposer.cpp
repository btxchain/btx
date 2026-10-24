// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_proposer.h>

namespace modelnet {

// An experiment propose request is held and proposes nothing.
SwarmProposerResult SwarmNoteProposer(const SwarmProposer& idea, std::string& err)
{
    SwarmProposerResult result;
    result.proposed = false;

    if (idea.idea_id.empty()) {
        result.code = "IDEA";
        err = "IDEA";
        result.proposed = false;
        return result;
    }
    if (idea.want_propose) {
        result.code = "HELD";
        err = "HELD";
        result.proposed = false;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.proposed = false;
    return result;
}

} // namespace modelnet
