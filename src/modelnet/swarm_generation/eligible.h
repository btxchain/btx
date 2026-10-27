// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_ELIGIBLE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_ELIGIBLE_H

#include <modelnet/swarm_generation/strategy.h>

#include <string>

namespace modelnet {

class SwarmGenerationEligible {
public:
    bool Apply(SwarmGenerationStrategy& strategy, bool license_allows, bool operator_grant, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_ELIGIBLE_H
