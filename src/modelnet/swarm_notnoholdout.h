// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOLDOUT_H
#define BTX_MODELNET_SWARM_NOTNOHOLDOUT_H

#include <string>

namespace modelnet {

/**
 * A local note about one holdout set. eval_id names the evaluation.
 * want_train asks this note to train.
 *
 * A holdout set is not a training run. trained and admitted stay false
 * on every path.
 */
struct SwarmNotNoHoldout {
    std::string eval_id;
    bool want_train{false};
};

/**
 * Outcome of noting a holdout set. trained and admitted stay false on
 * every path. A holdout set is not a training run.
 */
struct SwarmNotNoHoldoutResult {
    std::string code;
    bool trained{false};
    bool admitted{false};
};

/**
 * Note a holdout set without training on it.
 * Order, first match wins: an empty eval_id is EVAL.
 * want_train is NOT_RUN.
 * Otherwise the note is NOTED and err is cleared.
 * trained and admitted stay false on every path.
 * A holdout set is not a training run.
 */
SwarmNotNoHoldoutResult SwarmNoteNotNoHoldout(const SwarmNotNoHoldout& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOLDOUT_H
