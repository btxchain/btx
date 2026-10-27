// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/mark.h>

namespace modelnet {

void SwarmEarlyHaltMark::raise()
{
    m_set = true;
}

} // namespace modelnet
