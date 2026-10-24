// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STEPWORK_ADMIT_H
#define BITCOIN_MODELNET_SWARM_STEPWORK_ADMIT_H

#include <modelnet/swarm_experience/experience.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Decide whether Record may call the trainer.
 * An empty id is WORK. is_private true is PRIVATE_DATA.
 * steps below 1 is STEPS. An id already stored, which is a reward of
 * 0 or 1, is REPLAY. Those four paths store nothing and do not call Run.
 * A missing id has reward -1 and is not a replay.
 */
bool SwarmStepWorkAdmitRecord(const SwarmExperience& experience,
                              const std::string& id,
                              int64_t steps,
                              bool is_private,
                              std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STEPWORK_ADMIT_H
