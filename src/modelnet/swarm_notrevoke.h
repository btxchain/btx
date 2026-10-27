// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTREVOKE_H
#define BTX_MODELNET_SWARM_NOTREVOKE_H

#include <string>

namespace modelnet {

/**
 * A local note about one revoked member. want_read asks this note to show
 * that member reading a cache.
 *
 * A revoked member reading a cache has not been shown on a live cache.
 * allowed stays false on every path.
 */
struct SwarmNotRevoke {
    std::string member_id;
    bool want_read{false};
};

/**
 * Outcome of noting a revoked member. allowed stays false on every path:
 * a revoked member reading a cache has not been shown on a live cache.
 */
struct SwarmNotRevokeResult {
    std::string code;
    bool allowed{false};
};

/**
 * Note a revoked member without showing a live cache read.
 * Order, first match wins: an empty member_id is MEMBER.
 * want_read is NOT_LIVE.
 * Otherwise the note is NOTED and err is clear.
 * allowed stays false on every path. A revoked member reading a cache has
 * not been shown on a live cache.
 */
SwarmNotRevokeResult SwarmNoteNotRevoke(const SwarmNotRevoke& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTREVOKE_H
