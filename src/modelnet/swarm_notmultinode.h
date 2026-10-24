// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMULTINODE_H
#define BTX_MODELNET_SWARM_NOTMULTINODE_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Note that a run is not multi-node.
 *  published stays false, paired stays false, and tokens_per_sec stays 0.
 *  This record does not publish a run and does not pair nodes.
 */
struct SwarmNotMultiNode {
    std::string run_id;
    bool want_publish{false};
};

struct SwarmNotMultiNodeResult {
    std::string code;
    bool published{false};
    bool paired{false};
    int64_t tokens_per_sec{0};
};

/** Note a run that is not multi-node. Publication does not happen.
 *  Order, first match wins:
 *  1. An empty run_id is NODE. published stays false, paired stays false,
 *     tokens_per_sec stays 0, and err is NODE.
 *  2. want_publish is OUT_OF_SCOPE. published stays false, paired stays
 *     false, tokens_per_sec stays 0, and err is OUT_OF_SCOPE.
 *  3. Otherwise the note is NOTED. published stays false, paired stays
 *     false, tokens_per_sec stays 0, and err is cleared.
 */
SwarmNotMultiNodeResult SwarmNoteNotMultiNode(const SwarmNotMultiNode& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMULTINODE_H
