// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_execnbhd/order.h>

#include <algorithm>
#include <vector>

namespace modelnet {

bool SwarmExecNbhdPrecedes(const SwarmExecNbhdRecord& left, const SwarmExecNbhdRecord& right)
{
    if (left.rtt_ms != right.rtt_ms) {
        return left.rtt_ms < right.rtt_ms;
    }
    // std::string order compares the ids as bytes.
    return left.peer < right.peer;
}

void SwarmExecNbhdRank(std::vector<SwarmExecNbhdRecord>& rows)
{
    std::sort(rows.begin(), rows.end(), SwarmExecNbhdPrecedes);
}

} // namespace modelnet
