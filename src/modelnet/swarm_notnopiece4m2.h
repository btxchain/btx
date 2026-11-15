// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPIECE4M2_H
#define BTX_MODELNET_SWARM_NOTNOPIECE4M2_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmNotNoPiece4m2 {
    std::string piece_id;
    bool want_resize{false};
};

struct SwarmNotNoPiece4m2Result {
    std::string code;
    bool resized{false};
    int64_t bytes{0};
};

SwarmNotNoPiece4m2Result SwarmNoteNotNoPiece4m2(const SwarmNotNoPiece4m2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPIECE4M2_H
