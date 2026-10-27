// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT05_H
#define BTX_MODELNET_SWARM_FAULT05_H

#include <string>

namespace modelnet {

/**
 * Live fault 5: a worker disconnects after sending a result.
 * committed, bytes_moved, and broadcast stay false.
 * This function does not inject a fault, move bytes, or broadcast.
 */
struct SwarmFault05 {
    std::string worker_id;
    std::string work_id;
    bool result_sent{false};
    bool durable{false};
    bool payment_claim{false};
    bool want_reassign{false};
};

struct SwarmFault05Result {
    std::string code;
    bool committed{false};
    bool reassigned{false};
    bool recovered{false};
    bool payment_preserved{false};
    bool bytes_moved{false};
    bool broadcast{false};
};

/**
 * Empty worker_id or work_id is WORKER and sets err.
 * result_sent without durable is LOST and sets err.
 * durable with want_reassign is REASSIGNED, recovers, and clears err.
 * result_sent with durable is DURABLE, recovers, and clears err.
 * Otherwise NOTED, does not recover, and clears err.
 * payment_preserved follows payment_claim except on WORKER.
 */
SwarmFault05Result SwarmRecoverFault05(const SwarmFault05& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT05_H
