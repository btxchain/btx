// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/keep.h>

namespace modelnet {

std::string SwarmFsdpHoldKeep::first(const SwarmFsdpHoldBook& book, const std::string& name) const
{
    if (!book.contains(name)) return {};
    return book.name_of(name);
}

} // namespace modelnet
