// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNAT_H
#define BTX_MODELNET_SWARM_NOTNAT_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. want_traverse asks this note to traverse NAT
 * for that peer.
 *
 * Family discovery does not traverse NAT.
 * traversed stays false on every path.
 */
struct SwarmNotNat {
    std::string peer_id;
    bool want_traverse{false};
};

/**
 * Outcome of noting a NAT traversal request. traversed stays false on every
 * path: family discovery does not traverse NAT.
 */
struct SwarmNotNatResult {
    std::string code;
    bool traversed{false};
};

/**
 * Note a NAT traversal request without traversing.
 * Order, first match wins: an empty peer_id is PEER.
 * want_traverse is NO_NAT.
 * Otherwise the note is NOTED and err is clear.
 * traversed stays false on every path. Family discovery does not traverse NAT.
 */
SwarmNotNatResult SwarmNoteNotNat(const SwarmNotNat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNAT_H
