// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCONFLICT_H
#define BTX_MODELNET_SWARM_NOTNOCONFLICT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one conflict. want_settle asks this note to settle
 * that conflict.
 *
 * Conflicting evaluators settle nothing. settled stays false and atoms
 * stays 0 on every path.
 */
struct SwarmNotNoConflict {
    std::string report_id;
    bool conflicting{false};
    bool want_settle{false};
};

/**
 * Outcome of noting a conflict. settled stays false and atoms stays 0 on
 * every path. Conflicting evaluators settle nothing.
 */
struct SwarmNotNoConflictResult {
    std::string code;
    bool settled{false};
    int64_t atoms{0};
};

/**
 * Note a conflict without settling it or moving atoms.
 * Order, first match wins: an empty report_id is REPORT.
 * conflicting is CONFLICT, even when want_settle is false.
 * want_settle is HELD.
 * Otherwise the note is NOTED and err is clear.
 * settled stays false and atoms stays 0 on every path.
 * Conflicting evaluators settle nothing.
 */
SwarmNotNoConflictResult SwarmNoteNotNoConflict(const SwarmNotNoConflict& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCONFLICT_H
