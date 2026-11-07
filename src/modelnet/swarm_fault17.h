// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT17_H
#define BTX_MODELNET_SWARM_FAULT17_H

#include <string>

namespace modelnet {

/**
 * Live fault 17: a formerly authorized member attempts a new cache
 * access after revocation.
 *
 * Local recovery only. allowed, bytes_moved, and broadcast stay false
 * on every path. This function does not grant cache access, move bytes,
 * or broadcast.
 */
struct SwarmFault17 {
    std::string member_id;
    std::string page_id;
    bool revoked{false};
    bool want_read{false};
};

/**
 * Outcome of recovering live fault 17. allowed, bytes_moved, and
 * broadcast stay false: a revoked member is not given a new cache access.
 */
struct SwarmFault17Result {
    std::string code;
    bool allowed{false};
    bool bytes_moved{false};
    bool broadcast{false};
};

/**
 * Recover live fault 17 without allowing a new cache access.
 * Order, first match wins:
 * 1. An empty member_id or page_id is MEMBER. Every result bool stays
 *    false and err is MEMBER.
 * 2. revoked is REVOKED, even if want_read. allowed and bytes_moved
 *    stay false and err is REVOKED.
 * 3. want_read is HELD. allowed and bytes_moved stay false and err
 *    is cleared.
 * 4. Otherwise the note is NOTED. allowed and bytes_moved stay false
 *    and err is cleared.
 * allowed, bytes_moved, and broadcast stay false on every path.
 */
SwarmFault17Result SwarmRecoverFault17(const SwarmFault17& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT17_H
