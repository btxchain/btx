// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_ENGINE_PROBE_H
#define BTX_MODELNET_SWARM_KVFABRIC_ENGINE_PROBE_H

#include <modelnet/swarm_kvfabric/codes.h>
#include <modelnet/swarm_kvfabric/result.h>

#include <string>

namespace modelnet {

/**
 * Caller-supplied presence flag for a named engine.
 * present false, or an unknown name, is ENGINE_ABSENT.
 * present true on a known name is INSTALLED.
 * Installed is not qualified and is not advertised. No process is started.
 */
class KvFabricEngines {
public:
    SwarmKvFabricResult Probe(const std::string& name, bool present);
    const std::string& status() const { return m_status; }
    bool installed() const;
    bool advertised() const;
    bool qualified() const;
    bool process_started() const;

private:
    std::string m_status{kKvFabricEngineAbsent};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_ENGINE_PROBE_H
