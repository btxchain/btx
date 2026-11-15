// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_CODES_H

namespace modelnet {

/** sequence is below 1, or Refund ran before any sequence was stored. Nothing is stored. */
inline constexpr char kSwarmWatchHoldSequence[] = "SEQUENCE";

/** sequence is below the latest watched sequence. latest stays. */
inline constexpr char kSwarmWatchHoldStale[] = "STALE";

/** sequence equals the latest watched sequence. latest stays. */
inline constexpr char kSwarmWatchHoldReplay[] = "REPLAY";

/** Release, or a margin-satisfying Refund of a watched sequence. Nothing is broadcast. */
inline constexpr char kSwarmWatchHoldHeld[] = "HELD";

/** refund_height is below height + 160. Nothing is stored. */
inline constexpr char kSwarmWatchHoldMargin[] = "MARGIN";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_CODES_H
