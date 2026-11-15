// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/egress.h>

#include <modelnet/swarm_gradhold/seal.h>

namespace modelnet {

bool SwarmGradHoldEgress::Apply(const std::string& update_id, std::string& err) const
{
    err = SwarmGradHoldSeal{}.refusal(update_id);
    return false;
}

} // namespace modelnet
