// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/profile.h>

#include <modelnet/swarm_nodedefault/codes.h>

namespace modelnet {

const std::string& SwarmNodeDefaultProfile::launch_profile() const
{
    return m_profile;
}

bool SwarmNodeDefaultProfile::RenameProfile(const std::string&, std::string& err)
{
    err = kSwarmNodeDefaultHeld;
    return false;
}

} // namespace modelnet
