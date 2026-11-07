// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCKPTSAVE2_H
#define BTX_MODELNET_SWARM_NOTNOCKPTSAVE2_H

#include <string>

namespace modelnet {

struct SwarmNotNoCkptSave2 {
    std::string run_id;
    bool want_save{false};
};

struct SwarmNotNoCkptSave2Result {
    std::string code;
    bool saved{false};
    bool bytes_moved{false};
};

// A checkpoint save has not run and this note saves nothing.
SwarmNotNoCkptSave2Result SwarmNoteNotNoCkptSave2(const SwarmNotNoCkptSave2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCKPTSAVE2_H
