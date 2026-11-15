// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_descendants/average.h>

#include <modelnet/swarm_descendants/codes.h>
#include <modelnet/swarm_lineage.h>

namespace modelnet {

bool RefuseDescendantAverage(const std::string& left, const std::string& right, std::string& err)
{
    SwarmLineage lineage;
    std::string witness;
    // The witness book is empty and is discarded. Incompatible branches
    // are not folded into a head here.
    const bool averaged = lineage.Average(left, right, witness);
    (void)averaged;
    (void)witness;
    err = kDescendantNotAveraged;
    return false;
}

} // namespace modelnet
