// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOLD_H
#define BTX_MODELNET_SWARM_NOTNOHOLD_H

#include <string>

namespace modelnet {

/**
 * A local note about one split. split_id names the split. holdout marks
 * the split as a holdout. want_train asks this note to train on the split.
 *
 * A holdout split is not a training set and this note trains nothing.
 * trained and evaluated stay false on every path.
 */
struct SwarmNotNoHold {
    std::string split_id;
    bool holdout{false};
    bool want_train{false};
};

/**
 * Outcome of noting a split. trained and evaluated stay false on every
 * path. A holdout split is not a training set and this note trains nothing.
 */
struct SwarmNotNoHoldResult {
    std::string code;
    bool trained{false};
    bool evaluated{false};
};

/**
 * Note a split without training on it.
 * Order, first match wins: an empty split_id is SPLIT. holdout is
 * NOT_TRAIN, even when want_train is false. want_train is NOT_TRAIN.
 * Otherwise the note is NOTED and err is clear. A holdout split is not
 * a training set and this note trains nothing. trained and evaluated
 * stay false on every path.
 */
SwarmNotNoHoldResult SwarmNoteNotNoHold(const SwarmNotNoHold& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOLD_H
