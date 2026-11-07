// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REVOKE_H
#define BTX_MODELNET_SWARM_REVOKE_H

#include <string>

namespace modelnet {

// A revoked member reads no later page.
struct SwarmRevoke {
    std::string member_id;
    bool revoked;
    bool want_read;
};

struct SwarmRevokeResult {
    std::string code;
    bool read;
};

SwarmRevokeResult SwarmNoteRevoke(const SwarmRevoke& member, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REVOKE_H
