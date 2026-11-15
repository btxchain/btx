// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPROPOSER_H
#define BTX_MODELNET_SWARM_NOTPROPOSER_H

#include <string>

namespace modelnet {

/**
 * A local note about one cycle. want_propose asks this note to propose
 * for that cycle.
 *
 * This note does not select a weakness or schedule research.
 * proposed and scheduled stay false on every path.
 */
struct SwarmNotProposer {
    std::string cycle_id;
    bool want_propose{false};
};

/**
 * Outcome of noting a propose request. proposed and scheduled stay false
 * on every path: this note does not select a weakness or schedule research.
 */
struct SwarmNotProposerResult {
    std::string code;
    bool proposed{false};
    bool scheduled{false};
};

/**
 * Note a propose request without selecting a weakness or scheduling research.
 * Order, first match wins: an empty cycle_id is CYCLE. want_propose is
 * NOT_PROPOSED. Otherwise the note is NOTED and err is clear.
 * proposed and scheduled stay false on every path.
 */
SwarmNotProposerResult SwarmNoteNotProposer(const SwarmNotProposer& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPROPOSER_H
