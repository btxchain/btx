// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_domaingap.h>

namespace modelnet {

SwarmDomainQuorumResult SwarmNoteDomainQuorum(const SwarmDomainQuorum& note, std::string& err)
{
    SwarmDomainQuorumResult result;
    result.settled = false;
    if (note.candidate_id.empty() || note.domains < 1 || note.required_domains < 2) {
        result.code = "QUORUM";
        err = "QUORUM";
        return result;
    }
    if (note.domains < note.required_domains) {
        result.code = "DOMAIN";
        err = "DOMAIN";
        return result;
    }
    if (!note.outcomes_agree) {
        result.code = "SPLIT";
        err = "SPLIT";
        return result;
    }
    result.code = "HELD";
    result.settled = false;
    err.clear();
    return result;
}

} // namespace modelnet
