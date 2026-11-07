// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/profit.h>

#include <modelnet/swarm_paylabel/codes.h>
#include <modelnet/swarm_paylabel/vocabulary.h>

namespace modelnet {

bool SwarmPayLabelProfit::accept(const std::string& label, std::string& err) const
{
    if (SwarmPayLabelIsProfit(label)) {
        err = kSwarmPayLabelRefused;
        return false;
    }
    return true;
}

} // namespace modelnet
