// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT18_H
#define BTX_MODELNET_SWARM_FAULT18_H

#include <string>

namespace modelnet {

/**
 * Live fault 18: dataset authorization is withdrawn before training starts.
 * training, started, and broadcast stay false on every path.
 * This does not start a GPU job.
 */
struct SwarmFault18 {
    std::string dataset_id;
    std::string job_id;
    bool withdrawn{false};
    bool want_train{false};
};

/**
 * Outcome of live fault 18. training, started, and broadcast stay false:
 * withdrawn dataset authorization never starts training.
 */
struct SwarmFault18Result {
    std::string code;
    bool training{false};
    bool started{false};
    bool broadcast{false};
};

/**
 * Classify live fault 18 without starting a GPU job.
 * Order, first match wins:
 * 1. An empty dataset_id or job_id is DATASET. Every result bool stays
 *    false and err is DATASET.
 * 2. withdrawn is NOT_STARTED. training and started stay false.
 *    err is NOT_STARTED, even if want_train.
 * 3. want_train is HELD. training and started stay false. err is cleared.
 * 4. Otherwise NOTED. training and started stay false. err is cleared.
 * training, started, and broadcast stay false on every path.
 * This does not start a GPU job.
 */
SwarmFault18Result SwarmRecoverFault18(const SwarmFault18& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT18_H
