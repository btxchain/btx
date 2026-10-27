// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/role.h>

namespace modelnet {

bool SwarmNodeDefaultRole::seeder() const
{
    return m_seeder;
}

bool SwarmNodeDefaultRole::evaluator() const
{
    return m_evaluator;
}

int SwarmNodeDefaultRole::slots() const
{
    return m_slots;
}

} // namespace modelnet
