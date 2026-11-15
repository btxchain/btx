// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREGTEST_H
#define BTX_MODELNET_SWARM_NOTNOREGTEST_H

#include <string>

namespace modelnet {

struct SwarmNotNoRegtest {
    std::string chain_id;
    bool want_mine{false};
};

struct SwarmNotNoRegtestResult {
    std::string code;
    bool mined{false};
    bool broadcast{false};
};

// An isolated check mines nothing and broadcasts nothing.
// Order: empty chain_id is CHAIN; want_mine is NOT_MINED; otherwise NOTED
// and err is cleared. mined and broadcast stay false on every path.
SwarmNotNoRegtestResult SwarmNoteNotNoRegtest(const SwarmNotNoRegtest& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREGTEST_H
