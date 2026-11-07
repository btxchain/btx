// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_INTERRUPT_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_INTERRUPT_H

#include <modelnet/swarm_promotegate/candidate.h>
#include <modelnet/swarm_promotegate/flag.h>

#include <string>

namespace modelnet {

/**
 * Marks the staged promotion interrupted.
 * No staged candidate means Begin is not holding an id. That is STEP
 * and the flag is not set, so nothing is stored.
 * A staged candidate is marked. The active id is not an argument, so it
 * stays, including when it is "base". The staged id is not replaced.
 */
class SwarmPromoteInterrupt {
public:
    bool Apply(const SwarmPromoteCandidate& slot, SwarmPromoteFlag& flag, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_INTERRUPT_H
