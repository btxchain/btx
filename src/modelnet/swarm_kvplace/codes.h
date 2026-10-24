// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_CODES_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_CODES_H

namespace modelnet {

/** Empty fingerprint. Nothing is stored. */
inline constexpr char SWARM_KVPLACE_FINGERPRINT[] = "FINGERPRINT";

/** Quantization is not an accepted profile. Nothing is stored. */
inline constexpr char SWARM_KVPLACE_QUANTIZATION[] = "QUANTIZATION";

/** The fingerprint was already offered. The first record stays. */
inline constexpr char SWARM_KVPLACE_REPLAY[] = "REPLAY";

/** Prefix length is below 1. The prefix is not stored. */
inline constexpr char SWARM_KVPLACE_PREFIX[] = "PREFIX";

/** The fingerprint does not match a stored offer. Not an absent engine. */
inline constexpr char SWARM_KVPLACE_PREFIX_MISMATCH[] = "PREFIX_MISMATCH";

/** A named parent is not known. The prefix is not stored. */
inline constexpr char SWARM_KVPLACE_CAUSAL_GAP[] = "CAUSAL_GAP";

/** A cost input is negative, or the adjusted cost does not fit. Nothing is stored. */
inline constexpr char SWARM_KVPLACE_PRESSURE[] = "PRESSURE";

/** The chosen place is a transfer and no engine is present. No bytes move. */
inline constexpr char SWARM_KVPLACE_ENGINE_ABSENT[] = "ENGINE_ABSENT";

/** The chosen place is a transfer and an engine is present. No bytes move. */
inline constexpr char SWARM_KVPLACE_LOCAL[] = "LOCAL";

/** The pages cannot share a KV placement. Nothing is marked shared. */
inline constexpr char SWARM_KVPLACE_NOT_COMPAT[] = "NOT_COMPAT";

/** Winner when recomputing locally is the minimum, including ties it wins. */
inline constexpr char SWARM_KVPLACE_RECOMPUTE[] = "recompute";

/** Winner when the idle uncached place is the unique minimum. */
inline constexpr char SWARM_KVPLACE_IDLE[] = "idle";

/** Winner when routing to the owner is the unique minimum among later options. */
inline constexpr char SWARM_KVPLACE_ROUTE[] = "route";

/** Winner when a transfer is strictly cheaper than the other three. */
inline constexpr char SWARM_KVPLACE_TRANSFER[] = "transfer";

/** Family-only quantization. Membership is family, not KV, not cohort. */
inline constexpr char SWARM_KVPLACE_QUANT_4BIT[] = "4bit";

/** Cohort quantization. Requires a non-empty checkpoint and recipe. */
inline constexpr char SWARM_KVPLACE_QUANT_FULL[] = "full";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_CODES_H
