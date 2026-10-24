// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoquorum2.h>

#include <string>

namespace modelnet {

SwarmNotNoQuorum2Result SwarmNoteNotNoQuorum2(const SwarmNotNoQuorum2& note, std::string& err)
{
    SwarmNotNoQuorum2Result result;
    result.settled = false;
    result.atoms = 0;
    // A quorum needs distinct evaluators and distinct trust domains.
    if (note.quorum_id.empty()) {
        result.code = "QUORUM";
        result.settled = false;
        result.atoms = 0;
        err = "QUORUM";
        return result;
    }
    if (note.same_evaluator || note.same_domain) {
        result.code = "NOT_SETTLED";
        result.settled = false;
        result.atoms = 0;
        err = "NOT_SETTLED";
        return result;
    }
    if (note.want_settle) {
        result.code = "HELD";
        result.settled = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
