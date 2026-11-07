// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/same.h>

#include <string>

namespace modelnet {

bool SwarmTokenGateSame(const std::string& left, const std::string& right)
{
    if (left.size() != right.size()) return false;
    return left.compare(right) == 0;
}

} // namespace modelnet
