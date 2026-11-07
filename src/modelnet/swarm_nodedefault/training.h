// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_TRAINING_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_TRAINING_H

#include <modelnet/swarm_nodedefault/limits.h>

#include <string>

namespace modelnet {

/**
 * Training flag for the default node.
 * training() is false from construction. EnableTraining is HELD and
 * leaves it false. This does not spawn a process.
 */
class SwarmNodeDefaultTraining {
public:
    bool training() const;
    bool EnableTraining(std::string& err);

private:
    bool m_training{kSwarmNodeDefaultTraining};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_TRAINING_H
