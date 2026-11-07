// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SEALKEEP_H
#define BITCOIN_MODELNET_SWARM_SEALKEEP_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmSealKeep {
    std::string piece_id;
    bool sealed;
    bool want_open;
    int64_t bytes;
};

struct SwarmSealKeepResult {
    std::string code;
    bool opened;
    int64_t bytes_moved;
};

SwarmSealKeepResult SwarmKeepSealed(const SwarmSealKeep& piece, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SEALKEEP_H
