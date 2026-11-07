// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTIDENTITY_H
#define BITCOIN_MODELNET_SWARM_NOTIDENTITY_H

#include <string>

namespace modelnet {

struct SwarmNotIdentity {
    std::string node_id;
    bool want_bind{false};
};

struct SwarmNotIdentityResult {
    std::string code;
    bool bound{false};
};

/** Record a note only. This note does not bind a lab identity. */
SwarmNotIdentityResult SwarmNoteNotIdentity(const SwarmNotIdentity& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTIDENTITY_H
