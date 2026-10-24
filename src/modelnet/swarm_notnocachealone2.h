// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCACHEALONE2_H
#define BTX_MODELNET_SWARM_NOTNOCACHEALONE2_H

#include <string>

namespace modelnet {

struct SwarmNotNoCacheAlone2 {
    std::string cache_id;
    bool want_share{false};
};

struct SwarmNotNoCacheAlone2Result {
    std::string code;
    bool shared{false};
};

// A cache stands alone and is not shared.
SwarmNotNoCacheAlone2Result SwarmNoteNotNoCacheAlone2(const SwarmNotNoCacheAlone2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCACHEALONE2_H
