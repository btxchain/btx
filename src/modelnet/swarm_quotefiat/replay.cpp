// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/replay.h>

namespace modelnet {

bool SwarmQuoteFiatIsReplay(const SwarmQuoteFiatBook& book, const std::string& usd)
{
    if (usd.empty()) return false;
    return book.contains(usd);
}

} // namespace modelnet
