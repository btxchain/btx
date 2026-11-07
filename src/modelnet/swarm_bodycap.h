// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_BODYCAP_H
#define BTX_MODELNET_SWARM_BODYCAP_H

#include <cstdint>
#include <string>

namespace modelnet {

// The body cap stays 33554432 bytes. A raise request is held.
struct SwarmBodyCap {
    std::string body_id;
    bool want_raise;
};

struct SwarmBodyCapResult {
    std::string code;
    bool raised;
    int64_t bytes;
};

SwarmBodyCapResult SwarmKeepBodyCap(const SwarmBodyCap& body, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_BODYCAP_H
