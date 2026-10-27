// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULT04_H
#define BITCOIN_MODELNET_SWARM_FAULT04_H

#include <string>

namespace modelnet {

/** Live fault 4: training GPU crashes during checkpoint publication.
 *  No checkpoint is published. This record does not claim a GPU ran.
 */
struct SwarmFault04 {
    std::string job_id;
    bool checkpoint_saved{false};
    bool durable{false};
    bool want_publish{false};
};

struct SwarmFault04Result {
    std::string code;
    bool published{false};
    bool recovered{false};
    bool distributed{false};
    bool bytes_moved{false};
    bool broadcast{false};
};

SwarmFault04Result SwarmRecoverFault04(const SwarmFault04& in, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULT04_H
