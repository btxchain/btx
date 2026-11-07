// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCRIPTMESH_CLAIM_H
#define BITCOIN_MODELNET_SWARM_SCRIPTMESH_CLAIM_H

#include <modelnet/swarm_scriptmesh/types.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Build one SHA-256 claim leaf for hop and parse it back.
 * The leaf must pin the preimage length. code is SCRIPT when the leaf is
 * empty, the pin is absent, or the parsed hash or claimant differs.
 */
bool SwarmScriptMeshClaimLeaf(const SwarmScriptMeshHop& hop,
                              std::vector<unsigned char>& script,
                              std::string& code);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCRIPTMESH_CLAIM_H
