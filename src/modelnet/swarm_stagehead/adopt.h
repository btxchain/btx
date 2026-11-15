// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STAGEHEAD_ADOPT_H
#define BITCOIN_MODELNET_SWARM_STAGEHEAD_ADOPT_H

#include <modelnet/swarm_stagehead/active.h>
#include <modelnet/swarm_stagehead/candidate.h>
#include <modelnet/swarm_stagehead/memory.h>

#include <string>

namespace modelnet {

/**
 * Adopts the staged candidate when it is locally compatible.
 * No staged candidate is ADOPT. The active id stays.
 * local_compatible false is LOCAL_INCOMPATIBLE. The candidate stays staged
 * and nothing is remembered.
 * local_compatible true remembers the current active id, makes the candidate
 * the active id, clears the slot, and returns true.
 */
class SwarmStageAdopt {
public:
    bool Apply(SwarmStageActive& active, SwarmStageMemory& memory, SwarmStageCandidate& slot, bool local_compatible, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STAGEHEAD_ADOPT_H
