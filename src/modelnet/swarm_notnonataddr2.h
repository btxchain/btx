// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONATADDR2_H
#define BTX_MODELNET_SWARM_NOTNONATADDR2_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. peer_id names the peer.
 * nat records that the peer is behind NAT. want_publish asks
 * this note to publish an address.
 *
 * NAT traversal publishes no address. published stays false on every path.
 */
struct SwarmNotNoNatAddr2 {
    std::string peer_id;
    bool nat{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a peer. published stays false on every path.
 * NAT traversal publishes no address.
 */
struct SwarmNotNoNatAddr2Result {
    std::string code;
    bool published{false};
};

/**
 * Note a peer without publishing an address.
 * Order, first match wins: an empty peer_id is PEER. nat
 * true is NOT_PUBLISHED, even when want_publish is false. want_publish
 * is HELD. Otherwise the note is NOTED and err is cleared.
 * published stays false on every path.
 * NAT traversal publishes no address.
 */
SwarmNotNoNatAddr2Result SwarmNoteNotNoNatAddr2(const SwarmNotNoNatAddr2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONATADDR2_H
