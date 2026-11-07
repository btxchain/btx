// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_ERROR_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_ERROR_H

namespace modelnet {

/** Empty channel name. Nothing is stored. */
inline constexpr char kChannelSetChannel[] = "CHANNEL";

/** Capacity below 1. Nothing is stored. */
inline constexpr char kChannelSetCapacity[] = "CAPACITY";

/** A pubkey whose size is not MLDSA44_PUBKEY_SIZE. Nothing is stored. */
inline constexpr char kChannelSetKey[] = "KEY";

/** A channel is already open. The first channel stays. */
inline constexpr char kChannelSetNotOpened[] = "NOT_OPENED";

/** Fund or Refund was already accepted. The first result stays. */
inline constexpr char kChannelSetReplay[] = "REPLAY";

/** Payout before Fund. No payout is built. */
inline constexpr char kChannelSetNotFunded[] = "NOT_FUNDED";

/** Refund height is inside the close margin. No payout is built. */
inline constexpr char kChannelSetMargin[] = "MARGIN";

/** Cumulative is above capacity. The stored cumulative stays. */
inline constexpr char kChannelSetShort[] = "SHORT";

/** A later payout cumulative is below the stored cumulative. */
inline constexpr char kChannelSetStale[] = "STALE";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_ERROR_H
