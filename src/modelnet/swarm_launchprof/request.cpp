// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof/request.h>

#include <modelnet/swarm_launchprof/codes.h>
#include <modelnet/swarm_launchprof/gate.h>
#include <modelnet/swarm_launchprof/stay.h>

namespace modelnet {

bool SwarmLaunchProfileRequest::Apply(SwarmLaunchProfileBook& book, const std::string& name, std::string& err) const
{
    const SwarmLaunchProfileDecision decision = SwarmLaunchProfileDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmLaunchProfileReplay;
        } else {
            err = kSwarmLaunchProfileProfile;
        }
        return false;
    }
    err = SwarmLaunchProfileStay{}.refusal();
    return false;
}

} // namespace modelnet
