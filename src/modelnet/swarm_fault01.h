// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT01_H
#define BTX_MODELNET_SWARM_FAULT01_H

#include <string>

namespace modelnet {

/**
 * Local durable recovery for live fault 1: the coordinator disappears
 * with pending work.
 *
 * This note does not inject a live fault, spend, broadcast, or move
 * bytes. committed, bytes_moved, and broadcast stay false on every path.
 */
struct SwarmFault01 {
    std::string coord_id;
    std::string work_id;
    bool pending{false};
    bool durable{false};
    bool payment_claim{false};
    bool want_commit{false};
    bool want_reassign{false};
};

/**
 * Outcome of local durable recovery. committed, bytes_moved, and
 * broadcast stay false on every path.
 */
struct SwarmFault01Result {
    std::string code;
    bool committed{false};
    bool reassigned{false};
    bool recovered{false};
    bool payment_preserved{false};
    bool bytes_moved{false};
    bool broadcast{false};
};

/**
 * Recover a disappeared coordinator without committing, spending,
 * broadcasting, or moving bytes.
 * Order, first match wins: an empty coord_id or work_id is COORD.
 * want_commit is STALE. A disappeared leader commits nothing.
 * pending and not durable is LOST.
 * durable and want_reassign is REASSIGNED.
 * durable is DURABLE.
 * Otherwise the note is NOTED.
 * payment_preserved equals payment_claim except on COORD, where every
 * bool stays false. committed, bytes_moved, and broadcast stay false
 * on every path.
 */
SwarmFault01Result SwarmRecoverFault01(const SwarmFault01& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT01_H
