// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_BLANK_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_BLANK_H

#include <string>

namespace modelnet {

/**
 * Accepts a dispute id that can be opened.
 * An empty id is DISPUTE. The caller stores nothing on that result.
 */
class SwarmDisputeStayBlank {
public:
    bool accept(const std::string& dispute, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_BLANK_H
