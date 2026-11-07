// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_VOCABULARY_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_VOCABULARY_H

#include <string>

namespace modelnet {

/** True only when label is exactly "work-payment". No trim and no case fold. */
bool SwarmPayLabelIsWork(const std::string& label);

/** True only when label is exactly "profit-share". No trim and no case fold. */
bool SwarmPayLabelIsProfit(const std::string& label);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_VOCABULARY_H
