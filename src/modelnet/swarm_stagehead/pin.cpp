// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/pin.h>

namespace modelnet {

bool SwarmStagePin::Apply(SwarmStageCandidate& slot, std::string& err) const
{
    slot.clear();
    err.clear();
    return true;
}

} // namespace modelnet
