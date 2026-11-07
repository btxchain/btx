// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODISTINCTEV2_H
#define BTX_MODELNET_SWARM_NOTNODISTINCTEV2_H

#include <string>

namespace modelnet {

/**
 * A local note about one quorum. same_evaluator records that this note
 * shares an evaluator. want_count asks this note to count.
 *
 * The same evaluator is not a quorum. counted stays false on every path.
 */
struct SwarmNotNoDistinctEv2 {
    std::string quorum_id;
    bool same_evaluator{false};
    bool want_count{false};
};

/**
 * Outcome of noting a quorum. counted stays false on every path. The
 * same evaluator is not a quorum.
 */
struct SwarmNotNoDistinctEv2Result {
    std::string code;
    bool counted{false};
};

/**
 * Note a quorum without counting it. Order, first match wins: an empty
 * quorum_id is QUORUM. same_evaluator is NOT_QUORUM even when want_count
 * is false. want_count is HELD. Otherwise the note is NOTED and err is
 * cleared. counted stays false on every path. The same evaluator is not
 * a quorum.
 */
SwarmNotNoDistinctEv2Result SwarmNoteNotNoDistinctEv2(const SwarmNotNoDistinctEv2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODISTINCTEV2_H
