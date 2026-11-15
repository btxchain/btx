// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DOUBLEUSE_H
#define BTX_MODELNET_SWARM_DOUBLEUSE_H

#include <string>

namespace modelnet {

/**
 * A note that an outpoint is an escrow lot, channel collateral, or both.
 * The outpoint is an opaque string. Noting does not parse it, does not
 * broadcast, and never accepts the same outpoint in both roles.
 */
struct SwarmDoubleUse {
    std::string outpoint;
    bool escrow_lot{false};
    bool channel_collateral{false};
};

/**
 * Outcome of noting a double use. accepted is always false.
 */
struct SwarmDoubleUseResult {
    bool accepted{false};
    std::string code;
};

/**
 * Note an outpoint's roles without broadcasting.
 * An empty outpoint yields OUTPOINT.
 * Both escrow_lot and channel_collateral yield DOUBLE_USE.
 * Any other combination yields NOTED.
 * accepted is always false. err is the refusal code, or cleared on NOTED.
 */
SwarmDoubleUseResult SwarmNoteDoubleUse(const SwarmDoubleUse& use, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DOUBLEUSE_H
