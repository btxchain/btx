// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/book.h>

#include <modelnet/swarm_quotefiat/limits.h>
#include <modelnet/swarm_quotefiat/record.h>

#include <utility>

namespace modelnet {

bool SwarmQuoteFiatBook::contains(const std::string& usd) const
{
    if (usd.empty()) return false;
    return m_quotes.find(usd) != m_quotes.end();
}

std::string SwarmQuoteFiatBook::usd_of(const std::string& usd) const
{
    const auto found = m_quotes.find(usd);
    if (found == m_quotes.end()) return {};
    return found->second.usd();
}

std::size_t SwarmQuoteFiatBook::size() const
{
    return m_quotes.size();
}

int64_t SwarmQuoteFiatBook::atoms() const
{
    int64_t total = kSwarmQuoteFiatAtoms;
    for (const auto& entry : m_quotes) {
        total += entry.second.atoms();
    }
    return total;
}

bool SwarmQuoteFiatBook::usd_is_balance() const
{
    for (const auto& entry : m_quotes) {
        if (entry.second.usd_is_balance()) return true;
    }
    return false;
}

bool SwarmQuoteFiatBook::store(const std::string& usd)
{
    if (contains(usd)) return false;
    SwarmQuoteFiatRecord record = SwarmQuoteFiatRecord::Make(usd);
    if (!SwarmQuoteFiatRecordUsable(record)) return false;
    m_quotes.emplace(usd, std::move(record));
    return true;
}

} // namespace modelnet
