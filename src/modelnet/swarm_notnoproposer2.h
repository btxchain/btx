// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPROPOSER2_H
#define BTX_MODELNET_SWARM_NOTNOPROPOSER2_H

#include <string>

namespace modelnet {

/**
 * A local note about one proposer. want_propose asks this note to propose.
 *
 * An experiment proposer has not run and this note proposes nothing.
 * proposed stays false on every path.
 */
struct SwarmNotNoProposer2 {
    std::string proposer_id;
    bool want_propose{false};
};

/**
 * Outcome of noting a proposer request. proposed stays false on every
 * path. An experiment proposer has not run and this note proposes nothing.
 */
struct SwarmNotNoProposer2Result {
    std::string code;
    bool proposed{false};
};

/**
 * Note a proposer request without proposing.
 * Order, first match wins: an empty proposer_id is PROPOSER.
 * want_propose is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * proposed stays false on every path.
 * An experiment proposer has not run and this note proposes nothing.
 */
SwarmNotNoProposer2Result SwarmNoteNotNoProposer2(const SwarmNotNoProposer2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPROPOSER2_H
