// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_WORK_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_WORK_H

#include <string>

namespace modelnet {

/**
 * The only label that can be stored is exactly "work-payment".
 * An empty label and every other label are LABEL. The caller stores nothing.
 * profit-share is refused by SwarmPayLabelProfit before this check runs.
 */
class SwarmPayLabelWork {
public:
    bool accept(const std::string& label, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_WORK_H
