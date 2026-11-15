// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTLONGBASE_H
#define BTX_MODELNET_SWARM_NOTLONGBASE_H

#include <string>

namespace modelnet {

/**
 * A local note about one long base checkpoint. want_execute asks this
 * note to run that checkpoint and train from it.
 *
 * This note does not run a long base checkpoint or train. executed and
 * trained stay false on every path.
 */
struct SwarmNotLongBase {
    std::string checkpoint_id;
    bool want_execute{false};
};

/**
 * Outcome of noting a long base checkpoint. executed and trained stay
 * false on every path: this note does not run a long base checkpoint
 * or train.
 */
struct SwarmNotLongBaseResult {
    std::string code;
    bool executed{false};
    bool trained{false};
};

/**
 * Note a long base checkpoint without running it or training.
 * Order, first match wins: an empty checkpoint_id is CHECKPOINT.
 * want_execute is NOT_EXECUTED. Otherwise the note is NOTED and err
 * is clear. executed and trained stay false on every path. This note
 * does not run a long base checkpoint or train.
 */
SwarmNotLongBaseResult SwarmNoteNotLongBase(const SwarmNotLongBase& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTLONGBASE_H
