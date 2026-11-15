// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scriptroute.h>

#include <pqkey.h>
#include <script/pqm.h>

namespace modelnet {

SwarmScriptRoute SwarmBuildScriptRoute(const std::vector<SwarmScriptHop>& hops, std::string& err)
{
    SwarmScriptRoute route;
    route.qualified = false;
    route.secp_penalty = false;
    if (hops.size() < 2) {
        route.code = "HOPS";
        err = "HOPS";
        return route;
    }
    int previous = 0;
    for (std::size_t i = 0; i < hops.size(); ++i) {
        const SwarmScriptHop& hop = hops[i];
        if (hop.hash.size() != 32) {
            route.code = "PREIMAGE";
            err = "PREIMAGE";
            return route;
        }
        if (hop.claimant.size() != MLDSA44_PUBKEY_SIZE) {
            route.code = "KEY";
            err = "KEY";
            return route;
        }
        if (i == 0) {
            if (hop.expiry < 1) {
                route.code = "TIMEOUT";
                err = "TIMEOUT";
                return route;
            }
        } else if (hop.expiry < previous + 160) {
            route.code = "TIMEOUT";
            err = "TIMEOUT";
            return route;
        }
        previous = hop.expiry;
        const std::vector<unsigned char> script = BuildP2MRHTLCSha256Leaf(hop.hash, PQAlgorithm::ML_DSA_44, hop.claimant);
        if (script.empty() || !P2MRClaimLeafPinsPreimageLength(script)) {
            route.code = "SCRIPT";
            err = "SCRIPT";
            return route;
        }
        std::vector<unsigned char> parsed_hash;
        PQAlgorithm algo = PQAlgorithm::ML_DSA_44;
        std::vector<unsigned char> parsed_key;
        if (!ParseP2MRHTLCSha256Leaf(script, parsed_hash, algo, parsed_key) || parsed_hash != hop.hash || parsed_key != hop.claimant) {
            route.code = "SCRIPT";
            err = "SCRIPT";
            return route;
        }
        route.scripts.push_back(script);
    }
    route.scripts_ok = true;
    route.qualified = false;
    route.secp_penalty = false;
    route.code = "UNQUALIFIED";
    err = "UNQUALIFIED";
    return route;
}

} // namespace modelnet
