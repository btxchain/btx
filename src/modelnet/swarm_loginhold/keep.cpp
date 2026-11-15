// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/keep.h>

namespace modelnet {

std::string SwarmLoginHoldKeep::first(const SwarmLoginHoldBook& book, const std::string& name) const
{
    if (!book.contains(name)) return {};
    return book.name_of(name);
}

} // namespace modelnet
