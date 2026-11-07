// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DISPUTEOUT_H
#define BTX_MODELNET_SWARM_DISPUTEOUT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A settle request for one dispute. want_settle asks this record to settle
 * that dispute.
 *
 * A dispute settle request is held and settles no outpoint. settled stays
 * false and atoms stays 0 on every path.
 */
struct SwarmDisputeOut {
    std::string dispute_id;
    bool want_settle{false};
};

/**
 * Outcome of noting a dispute settle request. settled stays false and atoms
 * stays 0 on every path. A dispute settle request is held and settles no
 * outpoint.
 */
struct SwarmDisputeOutResult {
    std::string code;
    bool settled{false};
    int64_t atoms{0};
};

/**
 * Note a dispute settle request. It settles no outpoint and moves no atoms.
 * Order, first match wins: an empty dispute_id is DISPUTE. want_settle is
 * HELD. Otherwise the note is NOTED and err is clear.
 * settled stays false and atoms stays 0 on every path.
 */
SwarmDisputeOutResult SwarmNoteDisputeOut(const SwarmDisputeOut& dispute, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DISPUTEOUT_H
