// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SETTLEBUILD_SETTLE_H
#define BITCOIN_MODELNET_SWARM_SETTLEBUILD_SETTLE_H

#include <string>

namespace modelnet {

/**
 * Settlement stays refused.
 * claim_stored and refund_stored are observed and do not change the result.
 * err is UNQUALIFIED. The function returns false.
 */
bool SwarmSettleBuildRefuseSettle(bool claim_stored, bool refund_stored, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SETTLEBUILD_SETTLE_H
