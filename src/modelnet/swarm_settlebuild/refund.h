// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SETTLEBUILD_REFUND_H
#define BITCOIN_MODELNET_SWARM_SETTLEBUILD_REFUND_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Build one refund leaf and parse it back.
 * A timeout below 1 is TIMEOUT and leaves script empty.
 * An empty pubkey, or a pubkey whose size is not the chosen PQAlgorithm size,
 * is KEY. The leaf builder is not called in either case.
 * Otherwise BuildP2MRRefundLeaf runs. The leaf is kept only when
 * ParseP2MRRefundLeaf returns the same timeout and pubkey.
 * A miss is SCRIPT and script is cleared.
 */
bool SwarmSettleBuildMakeRefund(int64_t timeout,
                                const std::vector<unsigned char>& pubkey,
                                std::vector<unsigned char>& script,
                                std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SETTLEBUILD_REFUND_H
