// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/swarm_onechannel.h>

#include <modelnet/swarm_onechannel/flags.h>
#include <modelnet/swarm_onechannel/ledger.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmOneChannel::Reserve(const std::string& channel, std::string& err)
{
    return m_ledger.Reserve(channel, err);
}

bool SwarmOneChannel::BindPool(const std::string& pool, std::string& err)
{
    return m_ledger.BindPool(pool, err);
}

bool SwarmOneChannel::Fund(const std::string& pool, bool refund_bound, std::string& err)
{
    return m_ledger.Fund(pool, refund_bound, err);
}

bool SwarmOneChannel::Open(std::string& err)
{
    return m_ledger.Open(err);
}

bool SwarmOneChannel::Quote(const std::string& pool, const std::string& usd, std::string& err)
{
    return m_ledger.Quote(pool, usd, err);
}

std::string SwarmOneChannel::channel_id() const
{
    return m_ledger.channel_id();
}

std::size_t SwarmOneChannel::pool_count() const
{
    return m_ledger.pool_count();
}

bool SwarmOneChannel::bound(const std::string& pool) const
{
    return m_ledger.bound(pool);
}

bool SwarmOneChannel::funded(const std::string& pool) const
{
    return m_ledger.funded(pool);
}

bool SwarmOneChannel::holds_money(const std::string& pool) const
{
    return m_ledger.holds_money(pool);
}

std::string SwarmOneChannel::quote_of(const std::string& pool) const
{
    return m_ledger.quote_of(pool);
}

bool SwarmOneChannel::network_opened() const
{
    return m_flags.network_opened();
}

bool SwarmOneChannel::broadcast() const
{
    return m_flags.broadcast();
}

bool SwarmOneChannel::launched() const
{
    return m_flags.launched();
}

bool SwarmOneChannel::gpu() const
{
    return m_flags.gpu();
}

int64_t SwarmOneChannel::atoms_moved() const
{
    return m_flags.atoms_moved();
}

std::string SwarmOneChannel::automatic_spend() const
{
    return m_flags.automatic_spend();
}

} // namespace modelnet
