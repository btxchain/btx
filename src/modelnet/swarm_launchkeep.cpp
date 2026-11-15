// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchkeep.h>

namespace modelnet {

SwarmLaunchKeepResult SwarmKeepLaunchProfile(const SwarmLaunchKeep& profile, std::string& err)
{
    // The launch profile stays BTX035-LAUNCH-DECODER-2x64.
    if (profile.profile_id.empty()) {
        err = "PROFILE";
        return SwarmLaunchKeepResult{"PROFILE", false, "BTX035-LAUNCH-DECODER-2x64"};
    }
    if (profile.want_rename) {
        err = "HELD";
        return SwarmLaunchKeepResult{"HELD", false, "BTX035-LAUNCH-DECODER-2x64"};
    }
    err.clear();
    return SwarmLaunchKeepResult{"NOTED", false, "BTX035-LAUNCH-DECODER-2x64"};
}

} // namespace modelnet
