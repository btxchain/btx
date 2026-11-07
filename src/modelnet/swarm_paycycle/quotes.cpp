// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/quotes.h>

#include <modelnet/swarm_paycycle/codes.h>

#include <map>
#include <string>

namespace modelnet {

bool SwarmPayQuotes::Store(const std::string& pool, const std::string& usd, std::string& err)
{
    if (usd.empty()) {
        err = SWARM_PAYCYCLE_QUOTE;
        return false;
    }
    m_quotes[pool] = usd;
    err = SWARM_PAYCYCLE_NOT_BALANCE;
    return false;
}

std::string SwarmPayQuotes::get(const std::string& pool) const
{
    const auto it = m_quotes.find(pool);
    if (it == m_quotes.end()) return {};
    return it->second;
}

} // namespace modelnet
