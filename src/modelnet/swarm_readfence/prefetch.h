// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_PREFETCH_H
#define BITCOIN_MODELNET_SWARM_READFENCE_PREFETCH_H

#include <modelnet/swarm_readfence/engine.h>
#include <modelnet/swarm_readfence/warm.h>

#include <string>

namespace modelnet {

/**
 * Records a page id to prefetch.
 * While the engine status is not INSTALLED this is ENGINE_ABSENT and
 * records nothing. While INSTALLED the page id is recorded.
 * A recorded id moves no bytes and allocates no CUDA buffer.
 */
class SwarmReadPrefetch {
public:
    bool Apply(const SwarmReadEngine& engine, SwarmReadWarm& warm, const std::string& page, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_PREFETCH_H
