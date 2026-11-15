// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_REVOKE_H
#define BITCOIN_MODELNET_SWARM_READFENCE_REVOKE_H

#include <modelnet/swarm_readfence/roster.h>

#include <string>

namespace modelnet {

/**
 * Revokes a member.
 * An empty member is MEMBER and stores nothing.
 * A member who is already revoked is REPLAY and the roster stays.
 */
class SwarmReadRevoke {
public:
    bool Apply(SwarmReadRoster& roster, const std::string& member, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_REVOKE_H
