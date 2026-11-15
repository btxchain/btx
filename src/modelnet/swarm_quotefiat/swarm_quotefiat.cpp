// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/swarm_quotefiat.h>

#include <modelnet/swarm_quotefiat/keep.h>
#include <modelnet/swarm_quotefiat/quote.h>

namespace modelnet {

bool SwarmQuoteFiat::Quote(const std::string& usd, std::string& err)
{
    return SwarmQuoteFiatQuote{}.Apply(m_book, usd, err);
}

bool SwarmQuoteFiat::quoted(const std::string& usd) const
{
    return m_book.contains(usd);
}

std::string SwarmQuoteFiat::stored_usd(const std::string& usd) const
{
    return SwarmQuoteFiatKeep{}.first(m_book, usd);
}

std::size_t SwarmQuoteFiat::quote_count() const
{
    return m_book.size();
}

int64_t SwarmQuoteFiat::atoms() const
{
    return m_atoms.reported(m_book.atoms());
}

bool SwarmQuoteFiat::usd_is_balance() const
{
    if (m_book.usd_is_balance()) return true;
    return m_balance.is_balance();
}

bool SwarmQuoteFiat::broadcast() const
{
    return m_quiet.broadcast();
}

bool SwarmQuoteFiat::mined() const
{
    return m_quiet.mined();
}

int64_t SwarmQuoteFiat::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

std::string SwarmQuoteFiat::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

} // namespace modelnet
