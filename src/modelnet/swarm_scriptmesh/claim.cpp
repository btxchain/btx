// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptmesh/claim.h>

#include <pqkey.h>
#include <script/pqm.h>

namespace modelnet {

bool SwarmScriptMeshClaimLeaf(const SwarmScriptMeshHop& hop,
                              std::vector<unsigned char>& script,
                              std::string& code)
{
    script = BuildP2MRHTLCSha256Leaf(hop.hash, PQAlgorithm::ML_DSA_44, hop.claimant);
    if (script.empty() || !P2MRClaimLeafPinsPreimageLength(script)) {
        script.clear();
        code = kSwarmScriptMeshScript;
        return false;
    }

    std::vector<unsigned char> parsed_hash;
    std::vector<unsigned char> parsed_key;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    if (!ParseP2MRHTLCSha256Leaf(script, parsed_hash, algo, parsed_key) ||
        algo != PQAlgorithm::ML_DSA_44 ||
        parsed_hash != hop.hash ||
        parsed_key != hop.claimant) {
        script.clear();
        code = kSwarmScriptMeshScript;
        return false;
    }

    code.clear();
    return true;
}

} // namespace modelnet
