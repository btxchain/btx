// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_QUIET_H
#define BITCOIN_MODELNET_SWARM_READFENCE_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * Status this plane cannot change.
 * No bytes move. No process starts. No CUDA buffer is allocated.
 * Probe does not qualify or advertise an engine, whether the probe
 * installs a known name or reports the engine absent.
 */
class SwarmReadQuiet {
public:
    int64_t bytes_moved() const;
    bool qualified() const;
    bool advertised() const;
    bool process_started() const;
    bool cuda_buffer() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_QUIET_H
