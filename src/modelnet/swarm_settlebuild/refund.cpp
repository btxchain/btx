// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_settlebuild/refund.h>

#include <modelnet/swarm_settlebuild/algo.h>
#include <modelnet/swarm_settlebuild/codes.h>
#include <pqkey.h>
#include <script/pqm.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmSettleBuildMakeRefund(int64_t timeout,
                                const std::vector<unsigned char>& pubkey,
                                std::vector<unsigned char>& script,
                                std::string& err)
{
    script.clear();
    if (timeout < kSwarmSettleBuildMinTimeout) {
        err = kSwarmSettleBuildTimeout;
        return false;
    }
    if (!SwarmSettleBuildPubkeyAccepted(pubkey, err)) {
        return false;
    }

    const PQAlgorithm algo = SwarmSettleBuildAlgorithm();
    std::vector<unsigned char> built = BuildP2MRRefundLeaf(timeout, algo, pubkey);

    int64_t parsed_timeout{0};
    PQAlgorithm parsed_algo{algo};
    std::vector<unsigned char> parsed_key;
    const bool parsed = ParseP2MRRefundLeaf(built, parsed_timeout, parsed_algo, parsed_key);
    if (built.empty() || !parsed || parsed_algo != algo || parsed_timeout != timeout || parsed_key != pubkey) {
        built.clear();
        err = kSwarmSettleBuildScript;
        return false;
    }

    script = std::move(built);
    err.clear();
    return true;
}

} // namespace modelnet
