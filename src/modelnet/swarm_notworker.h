// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTWORKER_H
#define BITCOIN_MODELNET_SWARM_NOTWORKER_H

#include <string>

namespace modelnet {

struct SwarmNotWorker {
    std::string worker_id;
    bool want_drop{false};
};

struct SwarmNotWorkerResult {
    std::string code;
    bool dropped{false};
};

SwarmNotWorkerResult SwarmNoteNotWorker(const SwarmNotWorker& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTWORKER_H
