// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCRIPTMESH_REFUND_H
#define BITCOIN_MODELNET_SWARM_SCRIPTMESH_REFUND_H

#include <modelnet/swarm_scriptmesh/types.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Build one refund leaf for hop and parse it back.
 * The leaf uses hop.expiry as the timeout and hop.claimant as the key.
 * code is SCRIPT when the leaf is empty or the parse differs.
 */
bool SwarmScriptMeshMakeRefundLeaf(const SwarmScriptMeshHop& hop,
                                   std::vector<unsigned char>& script,
                                   std::string& code);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCRIPTMESH_REFUND_H
