// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notproposer.h>

#include <string>

namespace modelnet {

SwarmNotProposerResult SwarmNoteNotProposer(const SwarmNotProposer& note, std::string& err)
{
    SwarmNotProposerResult result;
    result.proposed = false;
    result.scheduled = false;
    // This note does not select a weakness or schedule research.
    if (note.cycle_id.empty()) {
        result.code = "CYCLE";
        result.proposed = false;
        result.scheduled = false;
        err = "CYCLE";
        return result;
    }
    if (note.want_propose) {
        result.code = "NOT_PROPOSED";
        result.proposed = false;
        result.scheduled = false;
        err = "NOT_PROPOSED";
        return result;
    }
    result.code = "NOTED";
    result.proposed = false;
    result.scheduled = false;
    err.clear();
    return result;
}

} // namespace modelnet
