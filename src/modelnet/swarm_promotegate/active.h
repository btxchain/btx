// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_ACTIVE_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_ACTIVE_H

#include <modelnet/swarm_promotegate/limits.h>

#include <string>

namespace modelnet {

/**
 * The active id. It starts as "base".
 * assign ignores an empty id, so the active id is never cleared.
 * An interrupted promotion does not call assign.
 */
class SwarmPromoteActive {
public:
    const std::string& id() const { return m_id; }
    void assign(const std::string& id);

private:
    std::string m_id{kSwarmPromoteBase};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_ACTIVE_H
