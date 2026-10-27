// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLATCAP_H
#define BITCOIN_MODELNET_SWARM_FLATCAP_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmFlatCap {
    std::string manifest_id;
    bool want_raise;
};

struct SwarmFlatCapResult {
    std::string code;
    bool raised;
    int64_t bytes;
};

SwarmFlatCapResult SwarmKeepFlatCap(const SwarmFlatCap& manifest, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLATCAP_H
