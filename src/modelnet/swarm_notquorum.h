// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTQUORUM_H
#define BTX_MODELNET_SWARM_NOTQUORUM_H

#include <string>

namespace modelnet {

/**
 * A local note about conflicting evaluator reports. want_settle asks this
 * note to treat those reports as a live quorum and settle.
 *
 * Conflicting evaluator reports are not a live quorum. settled stays false
 * on every path.
 */
struct SwarmNotQuorum {
    std::string report_id;
    bool want_settle{false};
};

/**
 * Outcome of noting conflicting evaluator reports. settled stays false on
 * every path: conflicting evaluator reports are not a live quorum.
 */
struct SwarmNotQuorumResult {
    std::string code;
    bool settled{false};
};

/**
 * Note conflicting evaluator reports without treating them as a live quorum.
 * Order, first match wins: an empty report_id is REPORT. want_settle is
 * NOT_QUORUM. Otherwise the note is NOTED and err is clear.
 * settled stays false on every path.
 */
SwarmNotQuorumResult SwarmNoteNotQuorum(const SwarmNotQuorum& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTQUORUM_H
