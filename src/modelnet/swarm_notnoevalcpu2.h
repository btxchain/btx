// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEVALCPU2_H
#define BTX_MODELNET_SWARM_NOTNOEVALCPU2_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_gpu asks this note to evaluate on a GPU.
 *
 * CPU evaluation stays the default. gpu stays false on every path.
 */
struct SwarmNotNoEvalCpu2 {
    std::string node_id;
    bool want_gpu{false};
};

/**
 * Outcome of noting a node. gpu stays false on every path. CPU evaluation
 * stays the default.
 */
struct SwarmNotNoEvalCpu2Result {
    std::string code;
    bool gpu{false};
};

/**
 * Note a node without starting GPU evaluation. Order, first match wins:
 * an empty node_id is NODE. want_gpu is HELD. Otherwise the note is NOTED
 * and err is cleared. gpu stays false on every path. CPU evaluation stays
 * the default.
 */
SwarmNotNoEvalCpu2Result SwarmNoteNotNoEvalCpu2(const SwarmNotNoEvalCpu2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEVALCPU2_H
