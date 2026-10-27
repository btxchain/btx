// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_QUOTE_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_QUOTE_H

#include <modelnet/swarm_quotefiat/book.h>

#include <string>

namespace modelnet {

/**
 * Quotes one usd string.
 * An empty usd is QUOTE and the book stays as it was.
 * A new non-empty usd is stored, then the call returns false with
 * NOT_BALANCE. The stored quote is not a balance and carries no atoms.
 * A second quote of the same usd is REPLAY and leaves the first quote.
 * Those checks run in that order.
 */
class SwarmQuoteFiatQuote {
public:
    bool Apply(SwarmQuoteFiatBook& book, const std::string& usd, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_QUOTE_H
