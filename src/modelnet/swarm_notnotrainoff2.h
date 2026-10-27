// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTRAINOFF2_H
#define BTX_MODELNET_SWARM_NOTNOTRAINOFF2_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_train asks this note to start training.
 *
 * Training stays off. training stays false and gpu stays false on every path.
 */
struct SwarmNotNoTrainOff2 {
    std::string node_id;
    bool want_train{false};
};

/**
 * Outcome of noting a training request. training stays false and gpu stays
 * false: training stays off.
 */
struct SwarmNotNoTrainOff2Result {
    std::string code;
    bool training{false};
    bool gpu{false};
};

/**
 * Note a training request without starting it. Order, first match wins: an
 * empty node_id is NODE. want_train is HELD. Otherwise the note is NOTED and
 * err is cleared. training stays false and gpu stays false on every path.
 * Training stays off.
 */
SwarmNotNoTrainOff2Result SwarmNoteNotNoTrainOff2(const SwarmNotNoTrainOff2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTRAINOFF2_H
