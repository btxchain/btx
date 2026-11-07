// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREGTEST2_H
#define BTX_MODELNET_SWARM_NOTNOREGTEST2_H

#include <string>

namespace modelnet {

struct SwarmNotNoRegtest2 {
    std::string check_id;
    bool isolated{false};
    bool want_mine{false};
};

struct SwarmNotNoRegtest2Result {
    std::string code;
    bool mined{false};
    int blocks{0};
};

// An isolated check mines nothing.
// Order: empty check_id is CHECK; isolated is NOT_MINED even when want_mine
// is false; want_mine is HELD; otherwise NOTED and err is cleared.
// mined stays false and blocks stays 0 on every path.
SwarmNotNoRegtest2Result SwarmNoteNotNoRegtest2(const SwarmNotNoRegtest2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREGTEST2_H
