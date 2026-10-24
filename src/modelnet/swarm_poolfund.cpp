// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_poolfund.h>

namespace modelnet {

bool SwarmPoolFund::Create(const std::string& pool, std::string& err)
{
    if (pool.empty()) {
        err = "POOL";
        return false;
    }
    if (m_pools.find(pool) != m_pools.end()) {
        err = "REPLAY";
        return false;
    }
    m_pools.emplace(pool, Row{});
    err.clear();
    return true;
}

bool SwarmPoolFund::Fund(const std::string& pool, int64_t atoms, std::string& err)
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end()) {
        err = "POOL";
        return false;
    }
    if (atoms < 1) {
        err = "ATOMS";
        return false;
    }
    if (it->second.funded) {
        err = "REPLAY";
        return false;
    }
    it->second.atoms = atoms;
    it->second.funded = true;
    err.clear();
    return true;
}

bool SwarmPoolFund::Advertised(const std::string& pool) const
{
    const auto it = m_pools.find(pool);
    return it != m_pools.end() && it->second.funded;
}

int64_t SwarmPoolFund::atoms(const std::string& pool) const
{
    const auto it = m_pools.find(pool);
    if (it == m_pools.end() || !it->second.funded) return 0;
    return it->second.atoms;
}

} // namespace modelnet
