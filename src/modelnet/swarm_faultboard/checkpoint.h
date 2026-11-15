// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_CHECKPOINT_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_CHECKPOINT_H

#include <string>

namespace modelnet {

/**
 * One checkpoint id for the swarm.
 * Keep stores the id and may replace an earlier id.
 * There is no clear. saved() is not a bit on this object.
 */
class SwarmFaultCheckpoint {
public:
    bool Keep(const std::string& id, std::string& err);
    bool kept() const;
    std::string id() const;

private:
    bool m_kept{false};
    std::string m_id;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_CHECKPOINT_H
