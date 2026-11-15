// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_FINISH_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_FINISH_H

#include <modelnet/swarm_promotegate/active.h>
#include <modelnet/swarm_promotegate/candidate.h>
#include <modelnet/swarm_promotegate/flag.h>
#include <modelnet/swarm_promotegate/memory.h>

#include <string>

namespace modelnet {

/**
 * Finishes a staged promotion that was not interrupted.
 * An interrupt mark is INTERRUPTED. The active id stays. The staged id
 * stays. The mark stays set.
 * No staged candidate is STEP. The active id stays.
 * A staged candidate that is not interrupted is adopted: the previous
 * active id is remembered, the candidate becomes the active id, the
 * staged slot is cleared, and the interrupt flag is cleared.
 */
class SwarmPromoteFinish {
public:
    bool Apply(SwarmPromoteActive& active, SwarmPromoteMemory& memory, SwarmPromoteCandidate& slot, SwarmPromoteFlag& flag, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_FINISH_H
