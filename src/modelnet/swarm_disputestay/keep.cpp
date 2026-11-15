// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disputestay/keep.h>

namespace modelnet {

std::string SwarmDisputeStayKeep::first(const SwarmDisputeStayBook& book, const std::string& dispute) const
{
    if (!book.contains(dispute)) return {};
    return book.dispute_of(dispute);
}

} // namespace modelnet
