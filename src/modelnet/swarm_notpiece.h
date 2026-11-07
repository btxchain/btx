// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPIECE_H
#define BTX_MODELNET_SWARM_NOTPIECE_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmNotPiece {
    std::string piece_id;
    int64_t size_bytes{0};
    bool want_split{false};
};

struct SwarmNotPieceResult {
    std::string code;
    bool split{false};
    bool bytes_moved{false};
};

// The piece size is 4 MiB and this note does not split or move bytes.
SwarmNotPieceResult SwarmNoteNotPiece(const SwarmNotPiece& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPIECE_H
