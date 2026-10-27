// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_PROFILE_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_PROFILE_H

#include <modelnet/swarm_nodedefault/limits.h>

#include <string>

namespace modelnet {

/**
 * Launch profile for the default node.
 * launch_profile() is BTX035-LAUNCH-DECODER-2x64 from construction.
 * RenameProfile is HELD for every name, including that same string, and
 * leaves the stored profile unchanged.
 */
class SwarmNodeDefaultProfile {
public:
    const std::string& launch_profile() const;
    bool RenameProfile(const std::string& name, std::string& err);

private:
    std::string m_profile{kSwarmNodeDefaultLaunchProfile};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_PROFILE_H
