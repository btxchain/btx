// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CKPTTRUST_LIMITS_H
#define BITCOIN_MODELNET_SWARM_CKPTTRUST_LIMITS_H

#include <cstdint>

namespace modelnet {

/** This plane moves no bytes. A recorded claim is not a payload. */
inline constexpr int64_t kSwarmCheckpointTrustBytesMoved = 0;

/** Trust does not touch a GPU. */
inline constexpr bool kSwarmCheckpointTrustGpu = false;

/** Trust does not launch work. */
inline constexpr bool kSwarmCheckpointTrustLaunched = false;

/** A stored claim is never lineage authority. trusted() stays false. */
inline constexpr bool kSwarmCheckpointTrustTrusted = false;

static_assert(kSwarmCheckpointTrustBytesMoved == 0, "a checkpoint trust moves no bytes");
static_assert(!kSwarmCheckpointTrustGpu, "a checkpoint trust does not use a gpu");
static_assert(!kSwarmCheckpointTrustLaunched, "a checkpoint trust does not launch");
static_assert(!kSwarmCheckpointTrustTrusted, "a checkpoint trust does not grant trust");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CKPTTRUST_LIMITS_H
