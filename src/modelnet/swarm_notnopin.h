// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPIN_H
#define BTX_MODELNET_SWARM_NOTNOPIN_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. node_id names the node.
 * pin_member records pin membership. want_seed asks this note to seed.
 *
 * Pin membership is not a public seed authority. seeded and published
 * stay false on every path.
 */
struct SwarmNotNoPin {
    std::string node_id;
    bool pin_member{false};
    bool want_seed{false};
};

/**
 * Outcome of noting a node. seeded and published stay false on every
 * path. Pin membership is not a public seed authority.
 */
struct SwarmNotNoPinResult {
    std::string code;
    bool seeded{false};
    bool published{false};
};

/**
 * Note a node without treating pin membership as a public seed authority.
 * Order, first match wins: an empty node_id is NODE. pin_member true is
 * NOT_SEED, even when want_seed is false. want_seed is HELD. Otherwise
 * the note is NOTED and err is cleared. seeded and published stay false
 * on every path. Pin membership is not a public seed authority.
 */
SwarmNotNoPinResult SwarmNoteNotNoPin(const SwarmNotNoPin& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPIN_H
