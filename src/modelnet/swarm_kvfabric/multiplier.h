// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_MULTIPLIER_H
#define BTX_MODELNET_SWARM_KVFABRIC_MULTIPLIER_H

#include <modelnet/swarm_kvfabric/result.h>

#include <cstdint>

namespace modelnet {

/**
 * Publish always stays HELD. The caller rate is not stored and is not published.
 */
class KvFabricMultiplier {
public:
    SwarmKvFabricResult Publish(int64_t rate);
    bool published() const;
    bool rate_stored() const;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_MULTIPLIER_H
