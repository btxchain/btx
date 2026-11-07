// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SETTLEBUILD_CODES_H
#define BITCOIN_MODELNET_SWARM_SETTLEBUILD_CODES_H

#include <cstddef>
#include <cstdint>

namespace modelnet {

/** SHA-256 payment hash length. Any other size is PREIMAGE and is not stored. */
inline constexpr std::size_t kSwarmSettleBuildHashSize = 32;

/** Lowest refund timeout BuildP2MRRefundLeaf will be asked to encode. */
inline constexpr int64_t kSwarmSettleBuildMinTimeout = 1;

/** Payment hash size is other than 32. Nothing is stored. */
inline constexpr char kSwarmSettleBuildPreimage[] = "PREIMAGE";

/** Pubkey is empty or its size is not the size of the chosen PQAlgorithm. */
inline constexpr char kSwarmSettleBuildKey[] = "KEY";

/** Refund timeout is below 1. Nothing is stored. */
inline constexpr char kSwarmSettleBuildTimeout[] = "TIMEOUT";

/** The builder output is empty or does not parse back to the same leaf. */
inline constexpr char kSwarmSettleBuildScript[] = "SCRIPT";

/** Settlement stays refused. No atoms move and nothing is broadcast. */
inline constexpr char kSwarmSettleBuildUnqualified[] = "UNQUALIFIED";

static_assert(kSwarmSettleBuildHashSize == 32, "payment hash is 32 bytes");
static_assert(kSwarmSettleBuildMinTimeout == 1, "refund timeout starts at 1");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SETTLEBUILD_CODES_H
