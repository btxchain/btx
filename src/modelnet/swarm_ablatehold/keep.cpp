// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/keep.h>

namespace modelnet {

std::string SwarmAblateHoldKeep::first(const SwarmAblateHoldBook& book, const std::string& name) const
{
    if (!book.contains(name)) return {};
    return book.name_of(name);
}

} // namespace modelnet
