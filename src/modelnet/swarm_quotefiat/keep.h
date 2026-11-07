// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_KEEP_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_KEEP_H

#include <modelnet/swarm_quotefiat/book.h>

#include <string>

namespace modelnet {

/**
 * Reads the quote already stored for usd.
 * An unknown usd reads as empty. This function does not write the book.
 */
class SwarmQuoteFiatKeep {
public:
    std::string first(const SwarmQuoteFiatBook& book, const std::string& usd) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_KEEP_H
