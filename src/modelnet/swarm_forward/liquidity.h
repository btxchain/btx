// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_LIQUIDITY_H
#define BITCOIN_MODELNET_SWARM_FORWARD_LIQUIDITY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Local amount checks for one forward.
 * Amount below 1 is ATOMS. Amount above remaining liquidity is SHORT.
 * Neither check changes the stored liquidity.
 */
class SwarmForwardLiquidity {
public:
    bool Atoms(int64_t amount, std::string& err) const;
    bool Fits(int64_t remaining, int64_t amount, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_LIQUIDITY_H
