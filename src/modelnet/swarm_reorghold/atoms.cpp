// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/atoms.h>

#include <limits>

namespace modelnet {

bool ReorgHoldAddAtoms(int64_t total, int64_t add, int64_t& out)
{
    if (total < 0 || add < 0) return false;
    const __int128 sum = static_cast<__int128>(total) + static_cast<__int128>(add);
    if (sum > static_cast<__int128>(std::numeric_limits<int64_t>::max())) return false;
    out = static_cast<int64_t>(sum);
    return true;
}

} // namespace modelnet
