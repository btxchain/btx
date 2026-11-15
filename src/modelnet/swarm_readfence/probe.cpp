// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/probe.h>

#include <modelnet/swarm_readfence/codes.h>
#include <modelnet/swarm_readfence/names.h>

namespace modelnet {

bool SwarmReadProbe::Apply(SwarmReadEngine& engine, const std::string& name, bool present, std::string& err) const
{
    if (!present || !SwarmReadKnownEngine(name) || !engine.Install(name)) {
        err = kSwarmReadEngineAbsent;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
