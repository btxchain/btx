// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/keep.h>

namespace modelnet {

std::string SwarmSchedWitnessKeep::first(const SwarmSchedWitnessBook& book, const std::string& witness) const
{
    if (!book.contains(witness)) return {};
    return book.witness_of(witness);
}

} // namespace modelnet
