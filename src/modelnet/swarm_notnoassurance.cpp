// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoassurance.h>

#include <string>

namespace modelnet {

SwarmNotNoAssuranceResult SwarmNoteNotNoAssurance(const SwarmNotNoAssurance& note, std::string& err)
{
    SwarmNotNoAssuranceResult result;
    result.proved = false;
    result.qualified = false;
    // proved and qualified stay false on every path. Cumulative assurance
    // is not proof of work and does not qualify a route.
    if (note.route_id.empty()) {
        result.code = "ROUTE";
        result.proved = false;
        result.qualified = false;
        err = "ROUTE";
        return result;
    }
    if (note.want_proof) {
        result.code = "NOT_WORK_PROOF";
        result.proved = false;
        result.qualified = false;
        err = "NOT_WORK_PROOF";
        return result;
    }
    result.code = "NOTED";
    result.proved = false;
    result.qualified = false;
    err.clear();
    return result;
}

} // namespace modelnet
