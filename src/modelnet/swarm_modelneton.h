// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MODELNETON_H
#define BITCOIN_MODELNET_SWARM_MODELNETON_H

#include <string>

namespace modelnet {

/**
 * A local note that ModelNet stays on for one node.
 * want_disable asks to turn ModelNet off. That request is held.
 */
struct SwarmModelNetOn {
    std::string node_id;
    bool want_disable{false};
};

/**
 * Outcome of keeping ModelNet on. disabled stays false on every path.
 */
struct SwarmModelNetOnResult {
    std::string code;
    bool disabled{false};
};

/**
 * Keep ModelNet on. Empty node_id is NODE. A disable request is HELD.
 * Otherwise the note is NOTED and err is clear. disabled stays false
 * on every path.
 */
SwarmModelNetOnResult SwarmKeepModelNetOn(const SwarmModelNetOn& node, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MODELNETON_H
