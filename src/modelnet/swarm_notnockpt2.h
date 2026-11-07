// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCKPT2_H
#define BTX_MODELNET_SWARM_NOTNOCKPT2_H

#include <string>

namespace modelnet {

struct SwarmNotNoCkpt2 {
    std::string run_id;
    bool want_save{false};
};

struct SwarmNotNoCkpt2Result {
    std::string code;
    bool saved{false};
    bool bytes_moved{false};
};

// A save request stores no checkpoint.
SwarmNotNoCkpt2Result SwarmNoteNotNoCkpt2(const SwarmNotNoCkpt2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCKPT2_H
