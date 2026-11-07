// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PROVIS_H
#define BTX_MODELNET_SWARM_PROVIS_H

#include <string>

namespace modelnet {

/**
 * A local note about one lineage. provisional marks the lineage as not
 * yet public. want_public asks this note to publish the lineage.
 *
 * This note does not publish a topic and does not open a socket.
 * published stays false on every path. No hostnames or IPs are used.
 */
struct SwarmProvisionalNote {
    std::string lineage_id;
    bool provisional{false};
    bool want_public{false};
};

/**
 * Outcome of noting a provisional lineage. published stays false: this
 * note does not publish a topic and does not open a socket.
 */
struct SwarmProvisionalResult {
    bool published{false};
    std::string code;
};

/**
 * Note a lineage without publishing it.
 * Order, first match wins: an empty lineage_id is LINEAGE. A provisional
 * lineage is PRIVATE, including when want_public is also true. A
 * provisional lineage stays private. want_public is HELD and err is
 * clear. Otherwise the note is NOTED and err is clear.
 * published stays false on every path. This note does not publish a
 * topic and does not open a socket. No hostnames or IPs are used.
 */
SwarmProvisionalResult SwarmNoteProvisional(const SwarmProvisionalNote& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PROVIS_H
