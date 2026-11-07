// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/blank.h>

#include <string>

namespace modelnet {

bool SwarmTokenGateBlank(const std::string& value)
{
    return value.empty();
}

} // namespace modelnet
