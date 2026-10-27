// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ARTIFACTRUN_LIMITS_H
#define BITCOIN_MODELNET_SWARM_ARTIFACTRUN_LIMITS_H

#include <modelnet/swarm_piecepipe/limits.h>

#include <cstdint>

namespace modelnet {

/** launched() stays this value. Load does not start a process. */
inline constexpr bool kSwarmArtifactRunLaunched = false;

/** gpu() stays this value. This plane does not use a device. */
inline constexpr bool kSwarmArtifactRunGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmArtifactRunBroadcast = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmArtifactRunAutomaticSpend[] = "0";

/** bytes_moved() stays this value. Bytes are not moved off the node. */
inline constexpr std::int64_t kSwarmArtifactRunBytesMoved = 0;

static_assert(kSwarmPiecePipePieceBytes == 4194304, "artifact pieces are at most 4194304 bytes");
static_assert(!kSwarmArtifactRunLaunched, "this plane does not launch");
static_assert(!kSwarmArtifactRunGpu, "this plane does not use a gpu");
static_assert(!kSwarmArtifactRunBroadcast, "this plane does not broadcast");
static_assert(kSwarmArtifactRunAutomaticSpend[0] == '0' && kSwarmArtifactRunAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmArtifactRunBytesMoved == 0, "bytes moved stays 0");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ARTIFACTRUN_LIMITS_H
