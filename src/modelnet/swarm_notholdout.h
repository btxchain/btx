// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTHOLDOUT_H
#define BTX_MODELNET_SWARM_NOTHOLDOUT_H

#include <string>

namespace modelnet {

/**
 * A local note about one loaded model. want_score asks this note to score
 * the model from a holdout rotation.
 *
 * Holdout rotation does not score a loaded model. scored stays false on
 * every path.
 */
struct SwarmNotHoldout {
    std::string model_id;
    bool want_score{false};
};

/**
 * Outcome of noting a holdout score request. scored stays false on every
 * path: holdout rotation does not score a loaded model.
 */
struct SwarmNotHoldoutResult {
    std::string code;
    bool scored{false};
};

/**
 * Note a holdout score request without scoring the loaded model.
 * Order, first match wins: an empty model_id is MODEL. want_score is
 * NOT_SCORED. Otherwise the note is NOTED and err is clear.
 * scored stays false on every path.
 */
SwarmNotHoldoutResult SwarmNoteNotHoldout(const SwarmNotHoldout& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTHOLDOUT_H
