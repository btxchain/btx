// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_BALANCE_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_BALANCE_H

namespace modelnet {

/**
 * Plane-level balance flag for a fiat quote.
 * The flag stays false. Quote has no setter that turns it on.
 */
class SwarmQuoteFiatBalance {
public:
    bool is_balance() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_BALANCE_H
