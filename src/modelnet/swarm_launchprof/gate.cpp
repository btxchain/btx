// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof/gate.h>

#include <modelnet/swarm_launchprof/blank.h>
#include <modelnet/swarm_launchprof/codes.h>
#include <modelnet/swarm_launchprof/replay.h>

namespace modelnet {

SwarmLaunchProfileDecision SwarmLaunchProfileDecide(const SwarmLaunchProfileBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmLaunchProfileBlank{}.accept(name, err)) {
        return SwarmLaunchProfileDecision{err, false};
    }
    if (SwarmLaunchProfileIsReplay(book, name)) {
        return SwarmLaunchProfileDecision{std::string{kSwarmLaunchProfileReplay}, false};
    }
    return SwarmLaunchProfileDecision{{}, true};
}

} // namespace modelnet
