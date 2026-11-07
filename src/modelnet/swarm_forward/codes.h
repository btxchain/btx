// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_CODES_H
#define BITCOIN_MODELNET_SWARM_FORWARD_CODES_H

namespace modelnet {

/** Open or forward named no channel, or the channel was never opened. */
inline constexpr char kSwarmForwardChannel[] = "CHANNEL";
/** Open liquidity is below 1. Nothing is stored. */
inline constexpr char kSwarmForwardLiquidity[] = "LIQUIDITY";
/** The channel was already opened, or the payment was already forwarded. */
inline constexpr char kSwarmForwardReplay[] = "REPLAY";
/** Forward amount is below 1. Liquidity is unchanged. */
inline constexpr char kSwarmForwardAtoms[] = "ATOMS";
/** Forward amount is above the remaining channel liquidity. */
inline constexpr char kSwarmForwardShort[] = "SHORT";
/** Outgoing expiry is below the incoming expiry plus the margin. */
inline constexpr char kSwarmForwardMargin[] = "MARGIN";
/** Forward was given an empty payment id. Nothing is stored. */
inline constexpr char kSwarmForwardPayment[] = "PAYMENT";

/**
 * Required route margin, in blocks. An outgoing expiry below
 * incoming_expiry + this value is MARGIN.
 */
inline constexpr int kSwarmForwardMarginBlocks{160};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_CODES_H
