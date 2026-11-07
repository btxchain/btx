// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/offer.h>

#include <modelnet/swarm_privfam/codes.h>
#include <modelnet/swarm_privfam/gate.h>

namespace modelnet {

bool SwarmPrivFamApply(SwarmPrivFamRoster& roster,
                        const std::string& family,
                        bool private_flag,
                        std::string& err)
{
    const std::string refusal = SwarmPrivFamRefusal(roster, family, private_flag);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!roster.store(family, private_flag)) {
        err = roster.contains(family) ? std::string{kSwarmPrivFamReplay} : std::string{kSwarmPrivFamFamily};
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
