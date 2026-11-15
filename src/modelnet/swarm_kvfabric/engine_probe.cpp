// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/engine_probe.h>

#include <modelnet/swarm_kvfabric/engine_names.h>

namespace modelnet {

SwarmKvFabricResult KvFabricEngines::Probe(const std::string& name, bool present)
{
    // The present flag is caller state. This probe does not fork, exec, or connect.
    if (!KvFabricKnownEngine(name) || !present) {
        m_status = kKvFabricEngineAbsent;
        return KvFabricResult(kKvFabricEngineAbsent);
    }
    m_status = kKvFabricInstalled;
    SwarmKvFabricResult result = KvFabricResult(kKvFabricInstalled);
    result.qualified = false;
    result.advertised = false;
    return result;
}

bool KvFabricEngines::installed() const
{
    return m_status == kKvFabricInstalled;
}

bool KvFabricEngines::advertised() const
{
    return false;
}

bool KvFabricEngines::qualified() const
{
    return false;
}

bool KvFabricEngines::process_started() const
{
    return false;
}

} // namespace modelnet
