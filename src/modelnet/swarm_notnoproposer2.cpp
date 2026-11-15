// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoproposer2.h>

#include <string>

namespace modelnet {

SwarmNotNoProposer2Result SwarmNoteNotNoProposer2(const SwarmNotNoProposer2& note, std::string& err)
{
    SwarmNotNoProposer2Result result;
    result.proposed = false;
    // An experiment proposer has not run and this note proposes nothing.
    if (note.proposer_id.empty()) {
        result.code = "PROPOSER";
        result.proposed = false;
        err = "PROPOSER";
        return result;
    }
    if (note.want_propose) {
        result.code = "HELD";
        result.proposed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.proposed = false;
    err.clear();
    return result;
}

} // namespace modelnet
