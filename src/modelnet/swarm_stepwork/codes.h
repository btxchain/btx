// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STEPWORK_CODES_H
#define BITCOIN_MODELNET_SWARM_STEPWORK_CODES_H

#include <cstdint>

namespace modelnet {

/** outcome_ppm for a stored step is steps multiplied by this. */
inline constexpr int64_t kSwarmStepWorkPpmPerStep = 1000;

/** Empty id, or Offer on an id that was never stored. Nothing is stored. */
inline constexpr char kSwarmStepWorkWork[] = "WORK";

/** is_private is true. Nothing is stored and the trainer is not called. */
inline constexpr char kSwarmStepWorkPrivateData[] = "PRIVATE_DATA";

/** steps is below 1. The trainer is not called. */
inline constexpr char kSwarmStepWorkSteps[] = "STEPS";

/** The id is already stored. The first outcome stays and no more steps run. */
inline constexpr char kSwarmStepWorkReplay[] = "REPLAY";

/** A GPU record was requested. No engine is present and nothing is stored. */
inline constexpr char kSwarmStepWorkEngineAbsent[] = "ENGINE_ABSENT";

static_assert(kSwarmStepWorkPpmPerStep == 1000, "one step stores 1000 ppm");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STEPWORK_CODES_H
