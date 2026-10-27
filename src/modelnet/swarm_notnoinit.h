// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOINIT_H
#define BTX_MODELNET_SWARM_NOTNOINIT_H

#include <string>

namespace modelnet {

/**
 * A local note about one initialization step. want_train asks this note
 * to train.
 *
 * Initialization is not a training step and saves no checkpoint.
 * trained and checkpoint_saved stay false on every path.
 */
struct SwarmNotNoInit {
    std::string step_id;
    bool want_train{false};
};

/**
 * Outcome of noting initialization. trained and checkpoint_saved stay
 * false on every path. Initialization is not a training step and saves
 * no checkpoint.
 */
struct SwarmNotNoInitResult {
    std::string code;
    bool trained{false};
    bool checkpoint_saved{false};
};

/**
 * Note initialization without training or saving a checkpoint.
 * Order, first match wins: an empty step_id is STEP. want_train is
 * NOT_RUN. Otherwise the note is NOTED and err is cleared. trained
 * and checkpoint_saved stay false on every path. Initialization is
 * not a training step and saves no checkpoint.
 */
SwarmNotNoInitResult SwarmNoteNotNoInit(const SwarmNotNoInit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOINIT_H
