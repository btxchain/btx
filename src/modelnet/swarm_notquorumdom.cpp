// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notquorumdom.h>

#include <string>

namespace modelnet {

SwarmNotQuorumDomResult SwarmNoteNotQuorumDom(const SwarmNotQuorumDom& note, std::string& err)
{
    SwarmNotQuorumDomResult result;
    result.settled = false;
    result.atoms = 0;
    // A quorum needs distinct evaluators and distinct trust domains.
    // This note settles nothing.
    if (note.quorum_id.empty()) {
        result.code = "QUORUM";
        result.settled = false;
        result.atoms = 0;
        err = "QUORUM";
        return result;
    }
    if (!note.distinct_evaluators) {
        result.code = "SAME_EVALUATOR";
        result.settled = false;
        result.atoms = 0;
        err = "SAME_EVALUATOR";
        return result;
    }
    if (!note.distinct_domains) {
        result.code = "SAME_DOMAIN";
        result.settled = false;
        result.atoms = 0;
        err = "SAME_DOMAIN";
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
