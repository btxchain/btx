// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_PROFIT_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_PROFIT_H

#include <string>

namespace modelnet {

/**
 * profit-share is not a label this plane will store.
 * A label exactly "profit-share" is REFUSED. The caller stores nothing.
 * Any other label is not this refusal.
 */
class SwarmPayLabelProfit {
public:
    bool accept(const std::string& label, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_PROFIT_H
