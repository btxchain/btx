// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DESCENDANTS_NODE_H
#define BITCOIN_MODELNET_SWARM_DESCENDANTS_NODE_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** One stored author score. Scores are not replaced by a mean. */
struct SwarmDescendantScore {
    std::string author;
    int64_t score{0};
};

/**
 * One stored descendant.
 * own_head is true for a baseline and for an incompatible fork.
 * A compatible fork keeps own_head false and stays on its parent head.
 * accepted is a score quorum flag. It does not promote the node to a head
 * and it does not graduate a realm.
 */
struct SwarmDescendantNode {
    std::string id;
    std::string parent;
    bool own_head{false};
    bool accepted{false};
    std::vector<std::string> channels;
    std::vector<SwarmDescendantScore> scores;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DESCENDANTS_NODE_H
