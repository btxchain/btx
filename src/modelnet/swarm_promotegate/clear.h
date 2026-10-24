// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_CLEAR_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_CLEAR_H

#include <modelnet/swarm_promotegate/candidate.h>
#include <modelnet/swarm_promotegate/flag.h>

#include <string>

namespace modelnet {

/**
 * Drops the staged candidate and the interrupt flag.
 * The active id is not an argument, so it stays.
 * Remembered previous state is also left untouched.
 * A later Begin can stage a new candidate into the empty slot.
 */
class SwarmPromoteClear {
public:
    bool Apply(SwarmPromoteCandidate& slot, SwarmPromoteFlag& flag, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_CLEAR_H
