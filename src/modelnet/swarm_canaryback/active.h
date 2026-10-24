// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_ACTIVE_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_ACTIVE_H

#include <modelnet/swarm_canaryback/limits.h>

#include <string>

namespace modelnet {

/**
 * The active id.
 * It starts as "base". Stage does not write it. Adopt replaces it
 * with the staged id. Regress writes the remembered previous id once
 * per Adopt. Graduate and Mine do not write it.
 */
class SwarmCanaryBackActive {
public:
    const std::string& get() const;
    void replace(const std::string& id);

private:
    std::string m_id{kSwarmCanaryBackBase};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_ACTIVE_H
