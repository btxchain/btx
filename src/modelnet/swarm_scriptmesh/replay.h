// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCRIPTMESH_REPLAY_H
#define BITCOIN_MODELNET_SWARM_SCRIPTMESH_REPLAY_H

#include <modelnet/swarm_scriptmesh/types.h>

#include <vector>

namespace modelnet {

/**
 * Remembers the hop list of a successful Build.
 * Same is true when that list is unchanged, which is the REPLAY case.
 */
class SwarmScriptMeshReplay {
public:
    bool Same(const std::vector<SwarmScriptMeshHop>& hops) const;
    void Remember(const std::vector<SwarmScriptMeshHop>& hops);
    void Forget();

private:
    bool m_armed{false};
    std::vector<SwarmScriptMeshHop> m_hops;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCRIPTMESH_REPLAY_H
