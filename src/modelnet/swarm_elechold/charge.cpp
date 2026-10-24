// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/charge.h>

#include <modelnet/swarm_elechold/codes.h>

namespace modelnet {

bool SwarmElecHoldCharge::Apply(int64_t atoms, std::string& err) const
{
    // atoms is not added. A measurement is not a charge.
    (void)atoms;
    err = kSwarmElecHoldHeld;
    return false;
}

} // namespace modelnet
