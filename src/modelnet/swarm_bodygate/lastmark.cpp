// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodygate/lastmark.h>

#include <cstdint>

namespace modelnet {

bool SwarmBodyLastIsHighest(const std::map<int64_t, SwarmBodyPiece>& pieces)
{
    if (pieces.empty()) {
        return false;
    }
    const int64_t highest = pieces.rbegin()->first;
    int64_t last_count = 0;
    int64_t last_index = -1;
    for (const auto& item : pieces) {
        if (!item.second.last) {
            continue;
        }
        ++last_count;
        last_index = item.first;
    }
    return last_count == 1 && last_index == highest;
}

} // namespace modelnet
