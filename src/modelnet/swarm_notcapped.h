// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCAPPED_H
#define BTX_MODELNET_SWARM_NOTCAPPED_H

#include <string>

namespace modelnet {

struct SwarmNotCapped {
    std::string node_id;
    int thread_count{0};
    bool want_train{false};
};

struct SwarmNotCappedResult {
    std::string code;
    bool training{false};
    int applied_threads{0};
};

// This note does not start training. A thread count above 64 is not applied.
SwarmNotCappedResult SwarmNoteNotCapped(const SwarmNotCapped& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCAPPED_H
