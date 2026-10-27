// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPIECE4_H
#define BTX_MODELNET_SWARM_NOTNOPIECE4_H

#include <string>
#include <cstdint>

namespace modelnet {

struct SwarmNotNoPiece4 {
    std::string piece_id;
    int64_t size_bytes{0};
    bool want_split{false};
};

struct SwarmNotNoPiece4Result {
    std::string code;
    bool split{false};
    bool bytes_moved{false};
};

// The piece split is 4 MiB and this note splits nothing.
SwarmNotNoPiece4Result SwarmNoteNotNoPiece4(const SwarmNotNoPiece4& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPIECE4_H
