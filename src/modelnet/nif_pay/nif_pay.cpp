// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_pay/nif_pay.h>

#include <modelnet/swarm_paycycle/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool NifPay::Open(const std::string& channel, const std::string& pool, std::string& err)
{
    if (!m_economy.Open(channel, pool, pool, err)) {
        if (channel.empty()) {
            err = SWARM_ECONOMYCLASS_ECONOMY;
        }
        return false;
    }
    err.clear();
    return true;
}

bool NifPay::Reserve(const std::string& id, int64_t atoms, std::string& err)
{
    if (atoms < static_cast<int64_t>(1)) {
        err = NIF_PAY_ATOMS;
        return false;
    }
    if (m_items.find(id) != m_items.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    Reservation row;
    row.atoms = atoms;
    m_items.emplace(id, row);
    m_reserved += atoms;
    err.clear();
    return true;
}

bool NifPay::Accept(const std::string& id, bool independent, std::string& err)
{
    const auto it = m_items.find(id);
    if (it == m_items.end()) {
        err = NIF_PAY_ATTEMPT;
        return false;
    }
    Reservation& row = it->second;
    if (row.decided) {
        err = NIFDT_REPLAY;
        return false;
    }
    row.decided = true;
    if (!independent) {
        err = NIF_PAY_NOT_ACCEPTED;
        return false;
    }
    m_earned += row.atoms;
    err.clear();
    return true;
}

bool NifPay::PayWork(const std::string& pool, const std::string& work, const std::string& worker, std::string& err)
{
    m_economy.PayWork(pool, work, worker, err);
    err = SWARM_PAYCYCLE_HELD;
    return false;
}

bool NifPay::Settle(std::string& err)
{
    m_settle.Settle(err);
    err = NIFDT_UNQUALIFIED;
    return false;
}

} // namespace modelnet
