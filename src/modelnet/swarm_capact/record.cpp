// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_capact/record.h>

namespace modelnet {

SwarmCapActGrantRecord SwarmCapActMakeGrant(const std::string& name)
{
    SwarmCapActGrantRecord record;
    record.name = name;
    return record;
}

bool SwarmCapActGrantUsable(const SwarmCapActGrantRecord& record)
{
    return !record.name.empty();
}

} // namespace modelnet
