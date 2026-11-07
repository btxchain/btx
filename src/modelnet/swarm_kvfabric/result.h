// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_RESULT_H
#define BTX_MODELNET_SWARM_KVFABRIC_RESULT_H

#include <modelnet/swarm_kvfabric/bytes.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Outcome of one KV fabric control-plane call. bytes_moved stays false. */
struct SwarmKvFabricResult {
    std::string code;
    bool advertised{false};
    bool qualified{false};
    bool published{false};
    bool bytes_moved{false};
    int64_t bytes{0};
};

inline SwarmKvFabricResult KvFabricResult(const std::string& code)
{
    SwarmKvFabricResult result;
    result.code = code;
    result.advertised = false;
    result.qualified = false;
    result.published = false;
    result.bytes_moved = KvFabricBytesMoved();
    result.bytes = 0;
    return result;
}

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_RESULT_H
