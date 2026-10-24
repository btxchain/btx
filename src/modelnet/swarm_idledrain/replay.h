// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_REPLAY_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_REPLAY_H

#include <string>

namespace modelnet {

/**
 * Shared refusal for a second Open and a second matching drain.
 * claimed returns true and sets err to REPLAY when the call already
 * happened. Otherwise err is left unchanged and the caller may proceed.
 * The worker count is not an argument, so a replay cannot move it.
 */
class SwarmIdleDrainReplay {
public:
    bool claimed(bool already, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_REPLAY_H
