// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPINPUB_H
#define BTX_MODELNET_SWARM_NOTNOPINPUB_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. node_id names the node.
 * pin_member records pin membership. want_publish asks this note to publish.
 *
 * Pin membership is not a public seed authority. published and authority
 * stay false on every path.
 */
struct SwarmNotNoPinPub {
    std::string node_id;
    bool pin_member{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a node. published and authority stay false on every
 * path. Pin membership is not a public seed authority.
 */
struct SwarmNotNoPinPubResult {
    std::string code;
    bool published{false};
    bool authority{false};
};

/**
 * Note a node without treating pin membership as a public seed authority.
 * Order, first match wins: an empty node_id is NODE. pin_member true is
 * NOT_AUTHORITY, even when want_publish is false. want_publish is
 * NOT_AUTHORITY. Otherwise the note is NOTED and err is cleared.
 * published and authority stay false on every path.
 * Pin membership is not a public seed authority.
 */
SwarmNotNoPinPubResult SwarmNoteNotNoPinPub(const SwarmNotNoPinPub& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPINPUB_H
