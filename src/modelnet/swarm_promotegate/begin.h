// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_BEGIN_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_BEGIN_H

#include <modelnet/swarm_promotegate/candidate.h>

#include <string>

namespace modelnet {

/**
 * Stages a candidate.
 * An empty candidate is HEAD and the slot is left unchanged.
 * A later non-empty candidate replaces the slot only.
 * The active id and the interrupt flag are not arguments, so neither changes.
 */
class SwarmPromoteBegin {
public:
    bool Place(SwarmPromoteCandidate& slot, const std::string& candidate, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_BEGIN_H
