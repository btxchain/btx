// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/work.h>

#include <modelnet/swarm_paylabel/codes.h>
#include <modelnet/swarm_paylabel/vocabulary.h>

namespace modelnet {

bool SwarmPayLabelWork::accept(const std::string& label, std::string& err) const
{
    if (!SwarmPayLabelIsWork(label)) {
        err = kSwarmPayLabelLabel;
        return false;
    }
    return true;
}

} // namespace modelnet
