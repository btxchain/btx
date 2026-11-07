// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/replay.h>

namespace modelnet {

bool SwarmSchedWitnessIsReplay(const SwarmSchedWitnessBook& book, const std::string& witness)
{
    if (witness.empty()) return false;
    return book.contains(witness);
}

} // namespace modelnet
