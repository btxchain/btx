// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/blank.h>

namespace modelnet {

bool SwarmPrivFamBlank(const std::string& family)
{
    return family.empty();
}

} // namespace modelnet
