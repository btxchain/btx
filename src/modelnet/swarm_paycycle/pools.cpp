// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/pools.h>

#include <modelnet/swarm_paycycle/codes.h>
#include <modelnet/swarm_paycycle/identity.h>

#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmPayPools::Publish(const std::string& chain, const std::string& lineage, const std::string& nonce,
                            const std::string& objective, const std::string& policy, std::string& err)
{
    if (chain.empty() || lineage.empty() || nonce.empty()) {
        err = SWARM_PAYCYCLE_POOL;
        return false;
    }
    if (!SwarmPayCycleAcceptObjective(objective)) {
        err = SWARM_PAYCYCLE_OBJECTIVE;
        return false;
    }
    const std::string id = SwarmPayCyclePoolId(chain, lineage, nonce, objective, policy);
    if (m_pools.find(id) != m_pools.end()) {
        err = SWARM_PAYCYCLE_REPLAY;
        return false;
    }
    Pool pool;
    pool.chain = chain;
    pool.lineage = lineage;
    pool.nonce = nonce;
    pool.objective = objective;
    pool.policy = policy;
    pool.funded = false;
    pool.balance = 0;
    m_pools.emplace(id, std::move(pool));
    err.clear();
    return true;
}

bool SwarmPayPools::RaiseEpoch(const std::string& pool, const std::string& new_policy, std::string& err)
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end()) {
        err = SWARM_PAYCYCLE_POOL;
        return false;
    }
    if (new_policy.empty()) {
        err = SWARM_PAYCYCLE_POLICY;
        return false;
    }
    const Pool& old = it->second;
    const std::string id = SwarmPayCyclePoolId(old.chain, old.lineage, old.nonce, old.objective, new_policy);
    if (m_pools.find(id) != m_pools.end()) {
        err = SWARM_PAYCYCLE_REPLAY;
        return false;
    }
    Pool created;
    created.chain = old.chain;
    created.lineage = old.lineage;
    created.nonce = old.nonce;
    created.objective = old.objective;
    created.policy = new_policy;
    created.funded = false;
    created.balance = 0;
    m_pools.emplace(id, std::move(created));
    err.clear();
    return true;
}

bool SwarmPayPools::Fund(const std::string& pool, bool refund_bound, std::string& err)
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end()) {
        err = SWARM_PAYCYCLE_POOL;
        return false;
    }
    if (!refund_bound) {
        err = SWARM_PAYCYCLE_FUNDING;
        return false;
    }
    it->second.funded = true;
    err.clear();
    return true;
}

int64_t SwarmPayPools::count() const
{
    return static_cast<int64_t>(m_pools.size());
}

bool SwarmPayPools::known(const std::string& pool) const
{
    return m_pools.find(pool) != m_pools.end();
}

bool SwarmPayPools::funded(const std::string& pool) const
{
    const auto it = m_pools.find(pool);
    return it != m_pools.end() && it->second.funded;
}

bool SwarmPayPools::holds_money() const
{
    for (const auto& entry : m_pools) {
        if (entry.second.funded) return true;
    }
    return false;
}

bool SwarmPayPools::holds_money(const std::string& pool) const
{
    return funded(pool);
}

int64_t SwarmPayPools::balance(const std::string& pool) const
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end()) return 0;
    return it->second.balance;
}

int64_t SwarmPayPools::PositiveFunded() const
{
    int64_t count = 0;
    for (const auto& entry : m_pools) {
        if (entry.second.funded && entry.second.balance > 0) {
            ++count;
        }
    }
    return count;
}

bool SwarmPayPools::Credit(const std::string& pool, int64_t atoms)
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end() || atoms < 1) return false;
    if (it->second.balance > std::numeric_limits<int64_t>::max() - atoms) return false;
    it->second.balance += atoms;
    return true;
}

bool SwarmPayPools::Move(const std::string& from_pool, const std::string& to_pool, int64_t atoms, std::string& err)
{
    const auto from_it = m_pools.find(from_pool);
    const auto to_it = m_pools.find(to_pool);
    if (from_it == m_pools.end() || to_it == m_pools.end() || !from_it->second.funded || !to_it->second.funded) {
        err = SWARM_PAYCYCLE_FUNDING;
        return false;
    }
    if (atoms < 1) {
        err = SWARM_PAYCYCLE_AMOUNT;
        return false;
    }
    Pool& from = from_it->second;
    Pool& to = to_it->second;
    if (from.balance < atoms) {
        err = SWARM_PAYCYCLE_NEGATIVE;
        return false;
    }
    if (&from != &to) {
        if (to.balance > std::numeric_limits<int64_t>::max() - atoms) {
            err = SWARM_PAYCYCLE_AMOUNT;
            return false;
        }
        from.balance -= atoms;
        to.balance += atoms;
    }
    err.clear();
    return true;
}

} // namespace modelnet
