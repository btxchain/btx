// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPIECE_H
#define BTX_MODELNET_SWARM_NOTNOPIECE_H

#include <string>
#include <cstdint>

namespace modelnet {

struct SwarmNotNoPiece {
    std::string piece_id;
    int64_t size_bytes{0};
    bool want_split{false};
};

struct SwarmNotNoPieceResult {
    std::string code;
    bool split{false};
    int64_t applied_bytes{0};
};

// A piece split is 4 MiB and this note splits nothing.
SwarmNotNoPieceResult SwarmNoteNotNoPiece(const SwarmNotNoPiece& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPIECE_H
