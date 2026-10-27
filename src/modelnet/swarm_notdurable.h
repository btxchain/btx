// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTDURABLE_H
#define BTX_MODELNET_SWARM_NOTDURABLE_H

#include <string>

namespace modelnet {

/**
 * A local note about one state. want_persist asks this note to write that
 * state into a store.
 *
 * This note does not write a store. persisted and bytes_moved stay false
 * on every path.
 */
struct SwarmNotDurable {
    std::string state_id;
    bool want_persist{false};
};

/**
 * Outcome of noting a persist request. persisted and bytes_moved stay false
 * on every path: this note does not write a store.
 */
struct SwarmNotDurableResult {
    std::string code;
    bool persisted{false};
    bool bytes_moved{false};
};

/**
 * Note a state without writing a store. Order, first match wins: an empty
 * state_id is STATE. want_persist is NOT_PERSISTED. Otherwise the note is
 * NOTED and err is clear. persisted and bytes_moved stay false on every path.
 */
SwarmNotDurableResult SwarmNoteNotDurable(const SwarmNotDurable& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTDURABLE_H
