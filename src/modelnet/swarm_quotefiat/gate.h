// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_GATE_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_GATE_H

#include <modelnet/swarm_quotefiat/book.h>

#include <string>

namespace modelnet {

/**
 * What Quote should do with usd.
 * code is QUOTE, REPLAY, or NOT_BALANCE.
 * store is true only for a new non-empty usd, which is kept and then
 * reported as NOT_BALANCE. This function does not modify the book.
 */
struct SwarmQuoteFiatDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Quote.
 * An empty usd is QUOTE and is not stored.
 * A usd already stored is REPLAY. The first quote stays.
 * Any other usd is NOT_BALANCE and may be stored.
 * QUOTE is decided before REPLAY.
 */
SwarmQuoteFiatDecision SwarmQuoteFiatDecide(const SwarmQuoteFiatBook& book, const std::string& usd);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_GATE_H
