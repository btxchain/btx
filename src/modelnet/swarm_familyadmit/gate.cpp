// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/gate.h>

#include <modelnet/swarm_familyadmit/codes.h>
#include <modelnet/swarm_familyadmit/compat.h>
#include <modelnet/swarm_familyadmit/replay.h>

namespace modelnet {

std::string SwarmFamilyAdmitRefusal(const SwarmFamilyAdmitRoster& roster,
                                     const std::string& peer,
                                     const std::string& family,
                                     const std::string& advertised_family,
                                     bool claims_compatible)
{
    const SwarmFamilyAdmitCompat compat = SwarmFamilyAdmitClassify(peer, family, advertised_family, claims_compatible);
    if (compat != SwarmFamilyAdmitCompat::Match) {
        const char* code = SwarmFamilyAdmitCompatCode(compat);
        if (code == nullptr) return std::string{kSwarmFamilyAdmitFamily};
        return std::string{code};
    }
    if (SwarmFamilyAdmitIsReplay(roster, peer)) return std::string{kSwarmFamilyAdmitReplay};
    return {};
}

} // namespace modelnet
