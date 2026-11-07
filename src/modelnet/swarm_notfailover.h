// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTFAILOVER_H
#define BITCOIN_MODELNET_SWARM_NOTFAILOVER_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Record that failover was not taken. This note does not claim a process was killed. */
struct SwarmNotFailover {
    std::string coord_id;
    bool want_publish{false};
};

struct SwarmNotFailoverResult {
    std::string code;
    bool published{false};
    int64_t failover_ms{0};
    bool continued{false};
};

SwarmNotFailoverResult SwarmNoteNotFailover(const SwarmNotFailover& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTFAILOVER_H
