// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTFINETUNE_H
#define BITCOIN_MODELNET_SWARM_NOTFINETUNE_H

#include <string>

namespace modelnet {

struct SwarmNotFineTune {
    std::string job_id;
    bool checkpoint_saved{false};
    bool want_publish{false};
};

struct SwarmNotFineTuneResult {
    std::string code;
    bool published{false};
    bool trained{false};
};

SwarmNotFineTuneResult SwarmNoteNotFineTune(const SwarmNotFineTune& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTFINETUNE_H
