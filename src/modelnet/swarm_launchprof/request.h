// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LAUNCHPROF_REQUEST_H
#define BITCOIN_MODELNET_SWARM_LAUNCHPROF_REQUEST_H

#include <modelnet/swarm_launchprof/book.h>

#include <string>

namespace modelnet {

/**
 * Records one rename and leaves the profile unchanged.
 * An empty name is PROFILE and the book stays as it was.
 * A new non-empty name is stored. The call returns false and err is HELD.
 * A second Rename of the same name is REPLAY and leaves the first name.
 * Those checks run in that order. The profile is not renamed and no bytes move.
 */
class SwarmLaunchProfileRequest {
public:
    bool Apply(SwarmLaunchProfileBook& book, const std::string& name, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LAUNCHPROF_REQUEST_H
