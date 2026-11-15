// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SEALOPEN_H
#define BITCOIN_MODELNET_SWARM_SEALOPEN_H

#include <string>

namespace modelnet {

struct SwarmSealOpen {
    std::string piece_id;
    bool sealed;
    bool want_open;
};

struct SwarmSealOpenResult {
    std::string code;
    bool opened;
};

SwarmSealOpenResult SwarmNoteSealOpen(const SwarmSealOpen& piece, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SEALOPEN_H
