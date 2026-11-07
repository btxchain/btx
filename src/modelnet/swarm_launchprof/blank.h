// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LAUNCHPROF_BLANK_H
#define BITCOIN_MODELNET_SWARM_LAUNCHPROF_BLANK_H

#include <string>

namespace modelnet {

/**
 * Accepts a name that can be recorded.
 * A name is an opaque short label. An empty name is PROFILE.
 * The caller stores nothing on that result.
 */
class SwarmLaunchProfileBlank {
public:
    bool accept(const std::string& name, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LAUNCHPROF_BLANK_H
