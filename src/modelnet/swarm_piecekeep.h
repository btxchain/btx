// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEKEEP_H
#define BITCOIN_MODELNET_SWARM_PIECEKEEP_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmPieceKeep {
    std::string piece_id;
    bool want_resize;
};

struct SwarmPieceKeepResult {
    std::string code;
    bool resized;
    int64_t bytes;
};

SwarmPieceKeepResult SwarmKeepPieceSplit(const SwarmPieceKeep& piece, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEKEEP_H
