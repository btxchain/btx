// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WORKPAY_MERGE_H
#define BITCOIN_MODELNET_SWARM_WORKPAY_MERGE_H

#include <string>

namespace modelnet {

/**
 * Counters are not merged. Returns false, sets err to NOT_MERGED, and
 * moves nothing.
 */
bool SwarmWorkMerge(std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WORKPAY_MERGE_H
