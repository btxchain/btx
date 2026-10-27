// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/vocabulary.h>

#include <modelnet/swarm_paylabel/limits.h>

namespace modelnet {

bool SwarmPayLabelIsWork(const std::string& label)
{
    return label == kSwarmPayLabelWork;
}

bool SwarmPayLabelIsProfit(const std::string& label)
{
    return label == kSwarmPayLabelProfit;
}

} // namespace modelnet
