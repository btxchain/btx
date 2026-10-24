// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREVOKE_H
#define BTX_MODELNET_SWARM_NOTNOREVOKE_H

#include <string>

namespace modelnet {

/**
 * A local note about one grant. want_revoke asks this note to revoke
 * the grant.
 *
 * This note revokes nothing and broadcasts nothing. revoked and
 * broadcast stay false on every path.
 */
struct SwarmNotNoRevoke {
    std::string grant_id;
    bool want_revoke{false};
};

/**
 * Outcome of noting a grant. revoked and broadcast stay false on every
 * path. This note revokes nothing and broadcasts nothing.
 */
struct SwarmNotNoRevokeResult {
    std::string code;
    bool revoked{false};
    bool broadcast{false};
};

/**
 * Note a grant without revoking it or broadcasting a revocation. Order,
 * first match wins: an empty grant_id is GRANT. want_revoke is HELD.
 * Otherwise the note is NOTED and err is clear. revoked and broadcast
 * stay false on every path. This note revokes nothing and broadcasts
 * nothing.
 */
SwarmNotNoRevokeResult SwarmNoteNotNoRevoke(const SwarmNotNoRevoke& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREVOKE_H
