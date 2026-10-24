// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptmesh/refund.h>

#include <pqkey.h>
#include <script/pqm.h>

namespace modelnet {

bool SwarmScriptMeshMakeRefundLeaf(const SwarmScriptMeshHop& hop,
                                   std::vector<unsigned char>& script,
                                   std::string& code)
{
    script = BuildP2MRRefundLeaf(hop.expiry, PQAlgorithm::ML_DSA_44, hop.claimant);

    int64_t locktime{0};
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    std::vector<unsigned char> parsed_key;
    if (script.empty() ||
        !ParseP2MRRefundLeaf(script, locktime, algo, parsed_key) ||
        algo != PQAlgorithm::ML_DSA_44 ||
        locktime != hop.expiry ||
        parsed_key != hop.claimant) {
        script.clear();
        code = kSwarmScriptMeshScript;
        return false;
    }

    code.clear();
    return true;
}

} // namespace modelnet
