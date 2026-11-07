// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTEXIT_H
#define BTX_MODELNET_SWARM_NOTEXIT_H

#include <string>

namespace modelnet {

/**
 * A local note about a mass channel exit during a reorganization.
 * batch_id names the batch. want_measure asks this note to measure
 * the exit.
 *
 * A mass channel exit during a reorganization has not been measured.
 * measured stays false and broadcast stays false on every path.
 */
struct SwarmNotExit {
    std::string batch_id;
    bool want_measure{false};
};

/**
 * Outcome of noting a mass channel exit. measured stays false and
 * broadcast stays false on every path: a mass channel exit during a
 * reorganization has not been measured.
 */
struct SwarmNotExitResult {
    std::string code;
    bool measured{false};
    bool broadcast{false};
};

/**
 * Note a mass channel exit without measuring it.
 * Order, first match wins: an empty batch_id is BATCH. want_measure
 * is MEASURE_REFUSED. Otherwise the note is NOTED and err is clear.
 * measured stays false and broadcast stays false on every path.
 * A mass channel exit during a reorganization has not been measured.
 */
SwarmNotExitResult SwarmNoteNotExit(const SwarmNotExit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTEXIT_H
