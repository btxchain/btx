// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_VRAM_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_VRAM_H

#include <modelnet/swarm_nodedefault/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Vram claim for the default node, in MiB.
 * vram_mib() is 0 from construction. ClaimVram with n other than 0 is
 * VRAM_ZERO and leaves 0. ClaimVram(0) is accepted and leaves 0.
 */
class SwarmNodeDefaultVram {
public:
    int64_t vram_mib() const;
    bool ClaimVram(int64_t n, std::string& err);

private:
    int64_t m_vram_mib{kSwarmNodeDefaultVramMib};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_VRAM_H
