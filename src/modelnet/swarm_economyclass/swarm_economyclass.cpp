// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_economyclass/swarm_economyclass.h>

#include <string>

namespace modelnet {
namespace {

const char* kChain = "btx";
const char* kObjective = "inference-service";
const char* kPolicy = "v1";

} // namespace

std::string SwarmEconomyClass::IdFor(const std::string& pool) const
{
    const char* nonce = pool == m_pool_a ? "1" : "2";
    return m_pay.pool_id(kChain, pool, nonce, kObjective, kPolicy);
}

bool SwarmEconomyClass::Open(const std::string& channel, const std::string& pool_a, const std::string& pool_b, std::string& err)
{
    if (channel.empty() || pool_a.empty() || pool_b.empty() || pool_a == pool_b) {
        err = SWARM_ECONOMYCLASS_ECONOMY;
        return false;
    }
    if (m_open) {
        err = channel == m_channel ? SWARM_ECONOMYCLASS_REPLAY : "NOT_OPENED";
        return false;
    }
    if (!m_one.Reserve(channel, err)) return false;
    if (!m_one.BindPool(pool_a, err)) return false;
    if (!m_one.BindPool(pool_b, err)) return false;
    if (!m_pay.Publish(kChain, pool_a, "1", kObjective, kPolicy, err)) return false;
    if (!m_pay.Publish(kChain, pool_b, "2", kObjective, kPolicy, err)) return false;
    m_pool_a = pool_a;
    m_pool_b = pool_b;
    const std::string id_a = IdFor(pool_a);
    if (!m_pay.Fund(id_a, true, err)) return false;
    if (!m_one.Fund(pool_a, true, err)) return false;
    m_channel = channel;
    m_open = true;
    err.clear();
    return true;
}

bool SwarmEconomyClass::PayWork(const std::string& pool, const std::string& work, const std::string& worker, std::string& err)
{
    if (!m_open || (pool != m_pool_a && pool != m_pool_b)) {
        err = "POOL";
        return false;
    }
    const std::string id = IdFor(pool);
    if (!m_pay.funded(id)) {
        err = "FUNDING";
        return false;
    }
    if (!m_pay.Lease(id, work, worker, err)) return false;
    if (m_pay.Pay(id, work, "work-payment", err)) {
        err = "HELD";
        return false;
    }
    if (err != "HELD") return false;
    if (!m_four.Credit("earned", 1, err)) return false;
    std::string merge_err;
    if (m_four.Merge(merge_err) || merge_err != "NOT_MERGED") {
        err = merge_err.empty() ? "NOT_MERGED" : merge_err;
        return false;
    }
    err = "HELD";
    return false;
}

bool SwarmEconomyClass::Quote(const std::string& pool, const std::string& usd, std::string& err)
{
    if (!m_open || (pool != m_pool_a && pool != m_pool_b)) {
        err = "POOL";
        return false;
    }
    return m_pay.Quote(IdFor(pool), usd, err);
}

bool SwarmEconomyClass::BuildLeaves(const std::vector<unsigned char>& payment_hash, const std::vector<unsigned char>& pubkey,
                                    int64_t timeout, std::string& err)
{
    if (!m_leaves.BuildClaim(payment_hash, pubkey, err)) return false;
    return m_leaves.BuildRefund(timeout, pubkey, err);
}

bool SwarmEconomyClass::Settle(std::string& err)
{
    return m_leaves.Settle(err);
}

bool SwarmEconomyClass::holds_money(const std::string& pool) const
{
    return m_one.holds_money(pool);
}

int64_t SwarmEconomyClass::earned_balance() const
{
    return m_four.Balance("earned");
}

bool SwarmEconomyClass::qualified() const
{
    return m_leaves.qualified();
}

bool SwarmEconomyClass::network_opened() const
{
    return m_one.network_opened();
}

bool SwarmEconomyClass::broadcast() const
{
    return m_pay.broadcast() || m_one.broadcast() || m_leaves.broadcast();
}

int64_t SwarmEconomyClass::atoms_moved() const
{
    return m_pay.atoms_moved() + m_one.atoms_moved() + m_leaves.atoms_moved();
}

std::string SwarmEconomyClass::automatic_spend() const
{
    return m_pay.automatic_spend();
}

const std::vector<unsigned char>& SwarmEconomyClass::claim_script() const
{
    return m_leaves.claim_script();
}

} // namespace modelnet
