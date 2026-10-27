// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_niche.h>

namespace modelnet {

SwarmNicheResult SwarmNoteNiche(const SwarmNicheCompare& compare, std::string& err)
{
    SwarmNicheResult result;
    result.compared = false;
    if (compare.left_niche.empty() || compare.right_niche.empty()) {
        result.code = "NICHE";
        err = "NICHE";
        return result;
    }
    if (compare.left_niche != compare.right_niche) {
        result.code = "SEPARATE";
        err = "SEPARATE";
        return result;
    }
    if (compare.want_compare) {
        result.code = "HELD";
        result.compared = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.compared = false;
    err.clear();
    return result;
}

} // namespace modelnet
