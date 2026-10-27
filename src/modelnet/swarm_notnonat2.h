// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONAT2_H
#define BTX_MODELNET_SWARM_NOTNONAT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. want_publish asks this note to publish
 * an address.
 *
 * NAT traversal publishes no address and moves no bytes, so published
 * stays false and bytes_moved stays false on every path.
 */
struct SwarmNotNoNat2 {
    std::string peer_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a peer. published stays false and bytes_moved
 * stays false on every path. NAT traversal publishes no address and
 * moves no bytes.
 */
struct SwarmNotNoNat2Result {
    std::string code;
    bool published{false};
    bool bytes_moved{false};
};

/**
 * Note a peer without publishing an address.
 * Order, first match wins: an empty peer_id is PEER.
 * want_publish is NOT_PUBLISHED. Otherwise the note is NOTED and err
 * is cleared. published stays false and bytes_moved stays false on
 * every path. NAT traversal publishes no address and moves no bytes.
 */
SwarmNotNoNat2Result SwarmNoteNotNoNat2(const SwarmNotNoNat2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONAT2_H
