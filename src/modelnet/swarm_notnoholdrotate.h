// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOLDROTATE_H
#define BTX_MODELNET_SWARM_NOTNOHOLDROTATE_H

#include <string>

namespace modelnet {

/**
 * A local note about one holdout. eval_id names the evaluation.
 * fixed_holdout marks a holdout that does not rotate. want_train asks
 * this note to train.
 *
 * A fixed holdout is not a rotating holdout and trains nothing.
 * trained and admitted stay false on every path.
 */
struct SwarmNotNoHoldRotate {
    std::string eval_id;
    bool fixed_holdout{false};
    bool want_train{false};
};

/**
 * Outcome of noting a holdout. trained and admitted stay false on every
 * path. A fixed holdout is not a rotating holdout and trains nothing.
 */
struct SwarmNotNoHoldRotateResult {
    std::string code;
    bool trained{false};
    bool admitted{false};
};

/**
 * Note a holdout without rotating it or training on it.
 * Order, first match wins: an empty eval_id is EVAL.
 * fixed_holdout is NOT_ROTATED even when want_train is false.
 * want_train is NOT_RUN.
 * Otherwise the note is NOTED and err is cleared.
 * trained and admitted stay false on every path.
 * A fixed holdout is not a rotating holdout and trains nothing.
 */
SwarmNotNoHoldRotateResult SwarmNoteNotNoHoldRotate(const SwarmNotNoHoldRotate& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOLDROTATE_H
