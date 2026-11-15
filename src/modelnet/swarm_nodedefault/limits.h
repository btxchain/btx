// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_LIMITS_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Model net stays on. Disable does not clear it. */
inline constexpr bool kSwarmNodeDefaultModelNetOn = true;

/** Launch profile. Rename does not replace it. */
inline constexpr char kSwarmNodeDefaultLaunchProfile[] = "BTX035-LAUNCH-DECODER-2x64";

/** Training stays off. */
inline constexpr bool kSwarmNodeDefaultTraining = false;

/** Private prompts stay off. */
inline constexpr bool kSwarmNodeDefaultPrivatePrompts = false;

/** Spend string before an operator-signed arm, and after every refusal. */
inline constexpr char kSwarmNodeDefaultSpendZero[] = "0";

/** Atoms actually moved. An arm records a bound and moves none. */
inline constexpr int64_t kSwarmNodeDefaultAtomsMoved = 0;

/** Fixed CPU thread count. */
inline constexpr int kSwarmNodeDefaultCpuThreads = 64;

/** Fixed vram, in MiB. */
inline constexpr int64_t kSwarmNodeDefaultVramMib = 0;

/** This node seeds. */
inline constexpr bool kSwarmNodeDefaultSeeder = true;

/** This node evaluates. */
inline constexpr bool kSwarmNodeDefaultEvaluator = true;

/** Fixed slot count. */
inline constexpr int kSwarmNodeDefaultSlots = 1;

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_LIMITS_H
