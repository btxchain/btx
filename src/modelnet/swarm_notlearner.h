// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTLEARNER_H
#define BTX_MODELNET_SWARM_NOTLEARNER_H

#include <string>

namespace modelnet {

/**
 * A local note about one trajectory. want_queue asks this note to queue
 * that trajectory for training.
 *
 * This note does not compute a reward or refresh a rollout model.
 * queued and trained stay false on every path.
 */
struct SwarmNotLearner {
    std::string trajectory_id;
    bool want_queue{false};
};

/**
 * Outcome of noting a learner request. queued and trained stay false
 * on every path. This note does not compute a reward or refresh a
 * rollout model.
 */
struct SwarmNotLearnerResult {
    std::string code;
    bool queued{false};
    bool trained{false};
};

/**
 * Note a learner request without computing a reward or refreshing a
 * rollout model. Order, first match wins: an empty trajectory_id is
 * TRAJECTORY. want_queue is NOT_QUEUED. Otherwise the note is NOTED
 * and err is clear. queued and trained stay false on every path.
 * This note does not compute a reward or refresh a rollout model.
 */
SwarmNotLearnerResult SwarmNoteNotLearner(const SwarmNotLearner& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTLEARNER_H
