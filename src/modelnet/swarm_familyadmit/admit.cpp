// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/admit.h>

#include <modelnet/swarm_familyadmit/codes.h>
#include <modelnet/swarm_familyadmit/gate.h>

namespace modelnet {

bool SwarmFamilyAdmitApply(SwarmFamilyAdmitRoster& roster,
                            const std::string& peer,
                            const std::string& family,
                            const std::string& advertised_family,
                            bool claims_compatible,
                            std::string& err)
{
    const std::string refusal = SwarmFamilyAdmitRefusal(roster, peer, family, advertised_family, claims_compatible);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!roster.store(peer, family)) {
        err = roster.contains(peer) ? std::string{kSwarmFamilyAdmitReplay} : std::string{kSwarmFamilyAdmitFamily};
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
