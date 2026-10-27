// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LAUNCHKEEP_H
#define BITCOIN_MODELNET_SWARM_LAUNCHKEEP_H

#include <string>

namespace modelnet {

struct SwarmLaunchKeep {
    std::string profile_id;
    bool want_rename;
};

struct SwarmLaunchKeepResult {
    std::string code;
    bool renamed;
    std::string profile;
};

SwarmLaunchKeepResult SwarmKeepLaunchProfile(const SwarmLaunchKeep& profile, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LAUNCHKEEP_H
