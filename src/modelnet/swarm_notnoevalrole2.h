// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEVALROLE2_H
#define BTX_MODELNET_SWARM_NOTNOEVALROLE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. no_device records that no device file is
 * present. want_train asks this note to train.
 *
 * Without a device file the node stays an evaluator and does not train.
 * training stays false on every path. Nothing broadcasts, spends,
 * launches, mines, or moves bytes.
 */
struct SwarmNotNoEvalRole2 {
    std::string node_id;
    bool no_device{false};
    bool want_train{false};
};

/**
 * Outcome of noting a no-device evaluator role. training stays false on
 * every path. Without a device file the node stays an evaluator and does
 * not train.
 */
struct SwarmNotNoEvalRole2Result {
    std::string code;
    bool training{false};
};

/**
 * Note a no-device evaluator role without training.
 * Order, first match wins: an empty node_id is NODE. If no_device is
 * true, the note is EVALUATOR even when want_train is false. want_train
 * is HELD. Otherwise the note is NOTED and err is cleared. training
 * stays false on every path.
 * Without a device file the node stays an evaluator and does not train.
 */
SwarmNotNoEvalRole2Result SwarmNoteNotNoEvalRole2(const SwarmNotNoEvalRole2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEVALROLE2_H
