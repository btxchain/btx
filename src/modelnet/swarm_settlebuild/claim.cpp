// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_settlebuild/claim.h>

#include <modelnet/swarm_settlebuild/algo.h>
#include <modelnet/swarm_settlebuild/codes.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <uint256.h>

#include <string>
#include <utility>
#include <vector>

namespace modelnet {

static_assert(kSwarmSettleBuildHashSize == uint256::size(), "payment hash is one SHA-256 digest");

bool SwarmSettleBuildMakeClaim(const std::vector<unsigned char>& payment_hash,
                               const std::vector<unsigned char>& pubkey,
                               std::vector<unsigned char>& script,
                               std::string& err)
{
    script.clear();
    if (payment_hash.size() != kSwarmSettleBuildHashSize) {
        err = kSwarmSettleBuildPreimage;
        return false;
    }
    if (!SwarmSettleBuildPubkeyAccepted(pubkey, err)) {
        return false;
    }

    const PQAlgorithm algo = SwarmSettleBuildAlgorithm();
    std::vector<unsigned char> built = BuildP2MRHTLCSha256Leaf(payment_hash, algo, pubkey);

    std::vector<unsigned char> parsed_hash;
    std::vector<unsigned char> parsed_key;
    PQAlgorithm parsed_algo{algo};
    const bool parsed = ParseP2MRHTLCSha256Leaf(built, parsed_hash, parsed_algo, parsed_key);
    const bool same = parsed && parsed_algo == algo && parsed_hash == payment_hash && parsed_key == pubkey;
    const bool pinned = P2MRClaimLeafPinsPreimageLength(built);
    if (built.empty() || !same || !pinned) {
        built.clear();
        err = kSwarmSettleBuildScript;
        return false;
    }

    script = std::move(built);
    err.clear();
    return true;
}

} // namespace modelnet
