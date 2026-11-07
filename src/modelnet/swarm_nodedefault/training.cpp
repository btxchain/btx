// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/training.h>

#include <modelnet/swarm_nodedefault/codes.h>

namespace modelnet {

bool SwarmNodeDefaultTraining::training() const
{
    return m_training;
}

bool SwarmNodeDefaultTraining::EnableTraining(std::string& err)
{
    err = kSwarmNodeDefaultHeld;
    return false;
}

} // namespace modelnet
