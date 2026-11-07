// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WORKPAY_CODES_H
#define BITCOIN_MODELNET_SWARM_WORKPAY_CODES_H

namespace modelnet {

/** Empty receipt, empty job, or a receipt that was never bound. */
inline constexpr char SWARM_WORK_RECEIPT[] = "RECEIPT";

/** atoms below 1, or a sum that would pass int64 max. Nothing is stored. */
inline constexpr char SWARM_WORK_ATOMS[] = "ATOMS";

/** The same receipt was bound or paid again. Atoms are not added again. */
inline constexpr char SWARM_WORK_REPLAY[] = "REPLAY";

/** A research key or a scheduler cannot be paid. Earned does not change. */
inline constexpr char SWARM_WORK_NOT_SIGNED[] = "NOT_SIGNED";

/** A fiat quote is not a balance. Nothing is stored. */
inline constexpr char SWARM_WORK_NOT_BALANCE[] = "NOT_BALANCE";

/** Counters are not merged. Nothing moves. */
inline constexpr char SWARM_WORK_NOT_MERGED[] = "NOT_MERGED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WORKPAY_CODES_H
