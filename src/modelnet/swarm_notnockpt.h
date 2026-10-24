// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCKPT_H
#define BTX_MODELNET_SWARM_NOTNOCKPT_H

#include <string>

namespace modelnet {

struct SwarmNotNoCkpt {
    std::string step_id;
    bool want_save{false};
};

struct SwarmNotNoCkptResult {
    std::string code;
    bool saved{false};
    bool distributed{false};
};

// An in-memory step is not a saved checkpoint and is not distributed training.
SwarmNotNoCkptResult SwarmNoteNotNoCkpt(const SwarmNotNoCkpt& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCKPT_H
