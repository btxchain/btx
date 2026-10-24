// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_MOTION_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_MOTION_H

#include <cstdint>

namespace modelnet {

/**
 * The placement plane does not move bytes, open a socket, or start an engine.
 * A transfer decision and a benchmark stay unmeasured.
 * There is no function here that returns a byte count above 0.
 */
std::int64_t SwarmKvPlaceBytesMoved();

/** No engine is launched by a placement decision. */
bool SwarmKvPlaceLaunched();

/** No GPU work is started by a placement decision. */
bool SwarmKvPlaceGpu();

/** A KV transfer is not a measured benchmark. */
bool SwarmKvPlaceMeasuredBenchmark();

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_MOTION_H
