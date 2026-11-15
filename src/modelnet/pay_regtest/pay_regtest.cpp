// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/pay_regtest/pay_regtest.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_economyclass/swarm_economyclass.h>
#include <modelnet/swarm_paycycle/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool PayRegtest::Open(const std::string& channel, const std::string& pool_a, const std::string& pool_b, std::string& err)
{
    if (pool_a == pool_b) {
        m_economy.Open(channel, pool_a, pool_b, err);
        err = PAY_REGTEST_ECONOMY;
        return false;
    }
    return m_economy.Open(channel, pool_a, pool_b, err);
}

bool PayRegtest::Pay(const std::string& pool, const std::string& work, const std::string& worker, std::string& err)
{
    const bool paid = m_economy.PayWork(pool, work, worker, err);
    if (err == SWARM_PAYCYCLE_HELD) {
        err = SWARM_PAYCYCLE_HELD;
        return false;
    }
    return paid;
}

bool PayRegtest::Settle(std::string& err)
{
    m_economy.Settle(err);
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool PayRegtest::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool PayRegtest::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool PayRegtest::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool PayRegtest::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool PayRegtest::network_opened() const
{
    return false;
}

} // namespace modelnet
