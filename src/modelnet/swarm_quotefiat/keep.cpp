// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/keep.h>

namespace modelnet {

std::string SwarmQuoteFiatKeep::first(const SwarmQuoteFiatBook& book, const std::string& usd) const
{
    if (!book.contains(usd)) return {};
    return book.usd_of(usd);
}

} // namespace modelnet
