// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONATPUB2_H
#define BTX_MODELNET_SWARM_NOTNONATPUB2_H

#include <string>

namespace modelnet {

/**
 * A local note. node_id names the note. want_publish asks this note
 * to publish an address.
 *
 * NAT traversal publishes no address. published stays false on every path.
 */
struct SwarmNotNoNatPub2 {
    std::string node_id;
    bool want_publish{false};
};

/**
 * Outcome of the note. published stays false on every path.
 * NAT traversal publishes no address.
 */
struct SwarmNotNoNatPub2Result {
    std::string code;
    bool published{false};
};

/**
 * Record the note without publishing an address.
 * Order, first match wins: an empty node_id is NODE. want_publish
 * is HELD. Otherwise the note is NOTED and err is cleared.
 * published stays false on every path.
 * NAT traversal publishes no address.
 */
SwarmNotNoNatPub2Result SwarmNoteNotNoNatPub2(const SwarmNotNoNatPub2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONATPUB2_H
