// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYSTAGE_PROFIT_SPLIT_H
#define BTX_MODELNET_SWARM_PAYSTAGE_PROFIT_SPLIT_H

#include <string>

namespace modelnet {

/**
 * Profit-share is refused. Returns false, sets err to REFUSED, and
 * moves nothing.
 */
bool SwarmPayProfitSplit(std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYSTAGE_PROFIT_SPLIT_H
