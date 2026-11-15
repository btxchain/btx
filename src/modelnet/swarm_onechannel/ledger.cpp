// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onechannel/ledger.h>

#include <modelnet/swarm_onechannel/bind.h>
#include <modelnet/swarm_onechannel/codes.h>
#include <modelnet/swarm_onechannel/fund.h>
#include <modelnet/swarm_onechannel/open.h>
#include <modelnet/swarm_onechannel/quote.h>
#include <modelnet/swarm_onechannel/record.h>
#include <modelnet/swarm_onechannel/reserve.h>

#include <cstddef>
#include <map>
#include <string>
#include <utility>

namespace modelnet {

const SwarmOneChannelPool* SwarmOneChannelLedger::FindBound(const std::string& pool) const
{
    if (pool.empty() || !SwarmOneChannelSeatReserved(m_seat)) {
        return nullptr;
    }
    const auto it = m_pools.find(pool);
    if (it == m_pools.end()) {
        return nullptr;
    }
    if (it->second.pool_id != pool) {
        return nullptr;
    }
    if (!SwarmOneChannelPoolOnChannel(it->second, m_seat.channel_id)) {
        return nullptr;
    }
    return &it->second;
}

bool SwarmOneChannelLedger::Reserve(const std::string& channel, std::string& err)
{
    if (!SwarmOneChannelDecideReserve(m_seat, channel, err)) {
        return false;
    }
    if (SwarmOneChannelSeatReserved(m_seat)) {
        err = SWARM_ONECHANNEL_NOT_OPENED;
        return false;
    }
    const std::string previous = m_seat.channel_id;
    m_seat.channel_id = channel;
    m_seat.reserved = true;
    if (!SwarmOneChannelSeatReserved(m_seat)) {
        m_seat.channel_id = previous;
        m_seat.reserved = false;
        err = SWARM_ONECHANNEL_CHANNEL;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmOneChannelLedger::BindPool(const std::string& pool, std::string& err)
{
    const bool reserved = SwarmOneChannelSeatReserved(m_seat);
    const bool already_bound = FindBound(pool) != nullptr;
    if (!SwarmOneChannelDecideBind(reserved, already_bound, pool, err)) {
        return false;
    }
    if (m_pools.find(pool) != m_pools.end()) {
        err = SWARM_ONECHANNEL_REPLAY;
        return false;
    }
    SwarmOneChannelPool created;
    if (!SwarmOneChannelMakePool(pool, m_seat.channel_id, created, err)) {
        return false;
    }
    if (!SwarmOneChannelPoolOnChannel(created, m_seat.channel_id)) {
        err = SWARM_ONECHANNEL_CHANNEL;
        return false;
    }
    m_pools.emplace(pool, std::move(created));
    err.clear();
    return true;
}

bool SwarmOneChannelLedger::Fund(const std::string& pool, bool refund_bound, std::string& err)
{
    auto it = m_pools.find(pool);
    const bool known = FindBound(pool) != nullptr && it != m_pools.end();
    const SwarmOneChannelPool* existing = known ? &it->second : nullptr;
    bool mark_funded = false;
    if (!SwarmOneChannelDecideFund(existing, refund_bound, mark_funded, err)) {
        return false;
    }
    if (!mark_funded || !known) {
        err = SWARM_ONECHANNEL_FUNDING;
        return false;
    }
    SwarmOneChannelApplyFund(it->second);
    err.clear();
    return true;
}

bool SwarmOneChannelLedger::Open(std::string& err)
{
    const std::string previous = m_seat.channel_id;
    const bool reserved = m_seat.reserved;
    const bool opened = SwarmOneChannelClassifyOpen(m_seat, err);
    m_seat.channel_id = previous;
    m_seat.reserved = reserved;
    return opened;
}

bool SwarmOneChannelLedger::Quote(const std::string& pool, const std::string& usd, std::string& err)
{
    auto it = m_pools.find(pool);
    const bool known = FindBound(pool) != nullptr && it != m_pools.end();
    const SwarmOneChannelPool* existing = known ? &it->second : nullptr;
    bool store = false;
    const bool accepted = SwarmOneChannelDecideQuote(existing, usd, store, err);
    if (store && known) {
        const bool holds_money = it->second.holds_money;
        SwarmOneChannelApplyQuote(it->second, usd);
        if (it->second.holds_money != holds_money) {
            it->second.holds_money = holds_money;
        }
    }
    return accepted;
}

std::string SwarmOneChannelLedger::channel_id() const
{
    if (!SwarmOneChannelSeatReserved(m_seat)) {
        return std::string();
    }
    return m_seat.channel_id;
}

std::size_t SwarmOneChannelLedger::pool_count() const
{
    if (!SwarmOneChannelSeatReserved(m_seat)) {
        return 0;
    }
    std::size_t count = 0;
    for (const auto& item : m_pools) {
        if (item.first == item.second.pool_id && SwarmOneChannelPoolOnChannel(item.second, m_seat.channel_id)) {
            ++count;
        }
    }
    return count;
}

bool SwarmOneChannelLedger::bound(const std::string& pool) const
{
    return FindBound(pool) != nullptr;
}

bool SwarmOneChannelLedger::funded(const std::string& pool) const
{
    const SwarmOneChannelPool* row = FindBound(pool);
    if (row == nullptr) {
        return false;
    }
    return row->funded;
}

bool SwarmOneChannelLedger::holds_money(const std::string& pool) const
{
    const SwarmOneChannelPool* row = FindBound(pool);
    if (row == nullptr) {
        return false;
    }
    return row->holds_money;
}

std::string SwarmOneChannelLedger::quote_of(const std::string& pool) const
{
    const SwarmOneChannelPool* row = FindBound(pool);
    if (row == nullptr) {
        return std::string();
    }
    return row->quote;
}

} // namespace modelnet
