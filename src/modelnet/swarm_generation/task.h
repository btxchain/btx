// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_TASK_H
#define BITCOIN_MODELNET_SWARM_GENERATION_TASK_H

#include <modelnet/swarm_generation/strategy.h>

#include <string>

namespace modelnet {

class SwarmGenerationSelectTask {
public:
    bool Apply(SwarmGenerationStrategy& strategy, const std::string& task, bool data_grant, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_TASK_H
