// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STAGEHEAD_PIN_H
#define BITCOIN_MODELNET_SWARM_STAGEHEAD_PIN_H

#include <modelnet/swarm_stagehead/candidate.h>

#include <string>

namespace modelnet {

/**
 * Clears the staged candidate.
 * The active id is not an argument of Apply, so the active id stays.
 * Remembered previous state is also left untouched.
 */
class SwarmStagePin {
public:
    bool Apply(SwarmStageCandidate& slot, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STAGEHEAD_PIN_H
