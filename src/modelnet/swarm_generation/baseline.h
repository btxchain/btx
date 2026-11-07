// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_BASELINE_H
#define BITCOIN_MODELNET_SWARM_GENERATION_BASELINE_H

#include <modelnet/swarm_generation/codes.h>

#include <string>

namespace modelnet {

/**
 * The general/stable label.
 * A specialist is a separate record and has no setter here.
 */
class SwarmGenerationBaseline {
public:
    const std::string& general_stable() const;

private:
    std::string m_general_stable{kSwarmGenerationGeneralStable};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_BASELINE_H
