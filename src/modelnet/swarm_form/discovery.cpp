// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/discovery.h>

namespace modelnet {

bool SwarmFormDiscovery::Consider(const fs::path& swarm_dir, SwarmFormMembership& members, const std::string& peer_id, const std::string& family_id, bool advertises_compatibility, std::string& err)
{
    if (peer_id.empty()) {
        err = "PEER";
        return false;
    }
    if (!members.formed()) {
        err = "MEMBERSHIP";
        return false;
    }
    const bool family_matches = !family_id.empty() && family_id == members.member().family_id;
    if (advertises_compatibility && !family_matches) {
        err = "FALSE_COMPAT";
        return false;
    }
    if (!family_matches) {
        err = "FAMILY";
        return false;
    }
    return members.Admit(swarm_dir, peer_id, err);
}

bool SwarmFormDiscovery::connects() const
{
    return false;
}

} // namespace modelnet
