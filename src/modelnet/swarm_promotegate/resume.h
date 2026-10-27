// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_RESUME_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_RESUME_H

#include <modelnet/swarm_promotegate/flag.h>

#include <string>

namespace modelnet {

/**
 * Resume does not adopt.
 * An interrupt mark is INTERRUPTED. The mark is the only argument, so
 * the staged id and the active id stay, and the mark stays set.
 * No interrupt mark is STEP. Nothing is adopted.
 */
class SwarmPromoteResume {
public:
    bool Apply(const SwarmPromoteFlag& flag, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_RESUME_H
