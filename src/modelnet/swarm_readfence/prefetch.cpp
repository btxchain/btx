// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/prefetch.h>

#include <modelnet/swarm_readfence/codes.h>

namespace modelnet {

bool SwarmReadPrefetch::Apply(const SwarmReadEngine& engine, SwarmReadWarm& warm, const std::string& page, std::string& err) const
{
    if (!engine.installed()) {
        err = kSwarmReadEngineAbsent;
        return false;
    }
    warm.Note(page);
    err.clear();
    return true;
}

} // namespace modelnet
