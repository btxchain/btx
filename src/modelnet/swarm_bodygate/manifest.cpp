// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodygate/manifest.h>

#include <modelnet/swarm_bodygate/limits.h>

namespace modelnet {

bool SwarmBodyManifest::SetEntries(int64_t count)
{
    if (count < 0 || count > kSwarmBodyGateManifestCap) {
        return false;
    }
    m_entries = count;
    return true;
}

} // namespace modelnet
