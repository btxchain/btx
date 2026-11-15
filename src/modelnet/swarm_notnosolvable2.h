// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSOLVABLE2_H
#define BTX_MODELNET_SWARM_NOTNOSOLVABLE2_H

#include <string>

namespace modelnet {

// An unsolved challenge does not move fitness.
struct SwarmNotNoSolvable2 {
    std::string challenge_id;
    bool unsolved{false};
    bool want_move{false};
};

struct SwarmNotNoSolvable2Result {
    std::string code;
    bool moved{false};
};

SwarmNotNoSolvable2Result SwarmNoteNotNoSolvable2(const SwarmNotNoSolvable2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSOLVABLE2_H
