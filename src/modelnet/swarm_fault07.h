// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT07_H
#define BTX_MODELNET_SWARM_FAULT07_H

#include <string>

namespace modelnet {

/**
 * Live fault 7: a cache owner disappears during transfer.
 * Local recovery only. bytes_moved, committed, and broadcast stay false.
 */
struct SwarmFault07 {
    std::string page_id;
    bool owner_present{false};
    bool durable{false};
    bool want_transfer{false};
};

/**
 * Outcome of a local note that a cache owner disappeared during transfer.
 * bytes_moved, committed, and broadcast stay false on every path.
 */
struct SwarmFault07Result {
    std::string code;
    bool recovered{false};
    bool bytes_moved{false};
    bool committed{false};
    bool broadcast{false};
};

/**
 * Classify a cache owner that disappeared during transfer.
 * Order, first match wins:
 * 1. An empty page_id is PAGE. Every result bool stays false and err is PAGE.
 * 2. A missing owner is INCOMPLETE. recovered and bytes_moved stay false.
 *    err is INCOMPLETE.
 * 3. want_transfer is HELD. recovered and bytes_moved stay false.
 *    err is cleared.
 * 4. A durable claim is DURABLE. recovered is set. bytes_moved stays false.
 *    err is cleared.
 * 5. Otherwise NOTED. recovered and bytes_moved stay false. err is cleared.
 * bytes_moved, committed, and broadcast stay false on every path.
 * This is local recovery only. It does not move bytes, commit, or broadcast.
 */
SwarmFault07Result SwarmRecoverFault07(const SwarmFault07& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT07_H
