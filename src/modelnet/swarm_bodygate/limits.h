// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_BODYGATE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_BODYGATE_LIMITS_H

#include <cstdint>

namespace modelnet {

/** A non-last piece is this many bytes. A last piece may be shorter. */
inline constexpr int64_t kSwarmBodyGatePieceBytes = 4194304;

/** Stored piece sizes may sum to this many bytes. A larger sum is refused. */
inline constexpr int64_t kSwarmBodyGateBodyCap = 33554432;

/** Flat manifest entry count. A larger count is refused. */
inline constexpr int64_t kSwarmBodyGateManifestCap = 16384;

inline constexpr char kSwarmBodyGateIndex[] = "INDEX";
inline constexpr char kSwarmBodyGateShort[] = "SHORT";
inline constexpr char kSwarmBodyGateReplay[] = "REPLAY";
inline constexpr char kSwarmBodyGateBody[] = "BODY";
inline constexpr char kSwarmBodyGateGap[] = "GAP";
inline constexpr char kSwarmBodyGateLast[] = "LAST";
inline constexpr char kSwarmBodyGateFlat[] = "FLAT";
inline constexpr char kSwarmBodyGateOk[] = "OK";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_BODYGATE_LIMITS_H
