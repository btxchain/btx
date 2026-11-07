// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSEEDEMPTY_H
#define BTX_MODELNET_SWARM_NOTNOSEEDEMPTY_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. node_id names the node.
 * want_seed asks this note to seed.
 *
 * Model DNS seeds stay empty. seeded stays false and seeds stays 0
 * on every path.
 */
struct SwarmNotNoSeedEmpty {
    std::string node_id;
    bool want_seed{false};
};

/**
 * Outcome of noting a node. seeded stays false and seeds stays 0
 * on every path. Model DNS seeds stay empty.
 */
struct SwarmNotNoSeedEmptyResult {
    std::string code;
    bool seeded{false};
    int seeds{0};
};

/**
 * Note a node without seeding model DNS seeds.
 * Order, first match wins: an empty node_id is NODE.
 * want_seed is EMPTY.
 * Otherwise the note is NOTED and err is cleared.
 * seeded stays false and seeds stays 0 on every path.
 * Model DNS seeds stay empty.
 */
SwarmNotNoSeedEmptyResult SwarmNoteNotNoSeedEmpty(const SwarmNotNoSeedEmpty& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSEEDEMPTY_H
