// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_CODES_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_CODES_H

namespace modelnet {

/** A second Open, or a second drain of any matching reason. The count stays. */
inline constexpr char kSwarmIdleDrainReplay[] = "REPLAY";

/** Admit would pass 64 workers. Nothing is added. */
inline constexpr char kSwarmIdleDrainCapped[] = "CAPPED";

/** Drain reason is not battery, thermal, or metered. Nothing changes. */
inline constexpr char kSwarmIdleDrainReason[] = "REASON";

/** Admit after a drain. Workers stay at 0. */
inline constexpr char kSwarmIdleDrainDrained[] = "DRAINED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_CODES_H
