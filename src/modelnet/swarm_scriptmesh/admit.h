// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCRIPTMESH_ADMIT_H
#define BITCOIN_MODELNET_SWARM_SCRIPTMESH_ADMIT_H

#include <modelnet/swarm_scriptmesh/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Decide whether a hop may be stored.
 * Missing fields, or a hash whose size is not 32, set PREIMAGE.
 * An empty claimant, or any claimant whose size is not MLDSA44_PUBKEY_SIZE,
 * sets KEY. An expiry that is not at least 160 above the previous stored hop
 * sets TIMEOUT. On failure the caller stores nothing.
 * Returns true and clears code when the hop may be stored.
 */
bool SwarmScriptMeshAdmitHop(const std::vector<SwarmScriptMeshHop>& stored,
                             const std::vector<unsigned char>& claimant,
                             const std::vector<unsigned char>& hash,
                             int64_t expiry,
                             bool fields_complete,
                             std::string& code);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCRIPTMESH_ADMIT_H
