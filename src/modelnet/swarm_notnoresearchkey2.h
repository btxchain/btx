// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORESEARCHKEY2_H
#define BTX_MODELNET_SWARM_NOTNORESEARCHKEY2_H

#include <cstdint>
#include <string>

namespace modelnet {

// A research key is not a spend key.
struct SwarmNotNoResearchKey2 {
    std::string key_id;
    bool research{false};
    bool want_spend{false};
};

struct SwarmNotNoResearchKey2Result {
    std::string code;
    bool spent{false};
    int64_t atoms{0};
};

SwarmNotNoResearchKey2Result SwarmNoteNotNoResearchKey2(const SwarmNotNoResearchKey2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORESEARCHKEY2_H
