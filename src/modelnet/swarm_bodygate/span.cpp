// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodygate/span.h>

#include <cstdint>
#include <limits>

namespace modelnet {

bool SwarmBodyIndexesContiguous(const std::map<int64_t, SwarmBodyPiece>& pieces)
{
    int64_t expected = 0;
    for (const auto& item : pieces) {
        if (item.first != expected) {
            return false;
        }
        if (expected == std::numeric_limits<int64_t>::max()) {
            return false;
        }
        ++expected;
    }
    return true;
}

} // namespace modelnet
