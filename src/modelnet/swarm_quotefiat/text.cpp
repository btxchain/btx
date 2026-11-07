// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/text.h>

namespace modelnet {

std::string SwarmQuoteFiatText::copy(const std::string& usd) const
{
    if (usd.empty()) return {};
    return usd;
}

} // namespace modelnet
