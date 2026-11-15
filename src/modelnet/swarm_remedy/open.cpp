// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/open.h>

#include <modelnet/swarm_remedy/codes.h>

namespace modelnet {

bool SwarmRemedyOpen::Create(int sequence, unsigned char fill, SwarmRevocation& out, std::string& err) const
{
    if (sequence < 1) {
        err = kSwarmRemedySequence;
        return false;
    }
    out = SwarmNewRevocation(sequence, fill);
    err.clear();
    return true;
}

} // namespace modelnet
