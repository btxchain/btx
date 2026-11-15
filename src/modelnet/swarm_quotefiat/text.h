// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_QUOTEFIAT_TEXT_H
#define BITCOIN_MODELNET_SWARM_QUOTEFIAT_TEXT_H

#include <string>

namespace modelnet {

/**
 * Copies usd as quote text.
 * The characters are kept as written. They are not parsed into atoms.
 * An empty usd copies nothing.
 */
class SwarmQuoteFiatText {
public:
    std::string copy(const std::string& usd) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_QUOTEFIAT_TEXT_H
