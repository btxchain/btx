// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_BLANK_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_BLANK_H

#include <string>

namespace modelnet {

/**
 * Accepts a receipt id that can be stored.
 * An empty receipt is RECEIPT. The caller stores nothing on that result.
 */
class SwarmDupBlank {
public:
    bool accept(const std::string& receipt, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_BLANK_H
