// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMEDIUM_H
#define BTX_MODELNET_SWARM_NOTMEDIUM_H

#include <string>

namespace modelnet {

/**
 * A local note about one medium adapter. want_execute asks this note to run
 * that adapter and train.
 *
 * This note does not run a medium adapter or train. executed and trained
 * stay false on every path.
 */
struct SwarmNotMedium {
    std::string adapter_id;
    bool want_execute{false};
};

/**
 * Outcome of noting a medium request. executed and trained stay false on
 * every path: this note does not run a medium adapter or train.
 */
struct SwarmNotMediumResult {
    std::string code;
    bool executed{false};
    bool trained{false};
};

/**
 * Note a medium request without running a medium adapter or training.
 * Order, first match wins: an empty adapter_id is ADAPTER. want_execute is
 * NOT_EXECUTED. Otherwise the note is NOTED and err is clear.
 * executed and trained stay false on every path. This note does not run a
 * medium adapter or train.
 */
SwarmNotMediumResult SwarmNoteNotMedium(const SwarmNotMedium& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMEDIUM_H
