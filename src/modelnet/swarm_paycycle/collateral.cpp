// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/collateral.h>

#include <modelnet/swarm_paycycle/codes.h>
#include <modelnet/swarm_paycycle/pools.h>

#include <cstdint>
#include <map>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmPayCollateral::Reserve(SwarmPayPools& pools, const std::string& pool, const std::string& outpoint,
                                 int64_t atoms, const std::string& role, std::string& err)
{
    if (atoms < 1 || outpoint.empty()) {
        err = SWARM_PAYCYCLE_COLLATERAL;
        return false;
    }
    if (!pools.known(pool)) {
        err = SWARM_PAYCYCLE_POOL;
        return false;
    }
    if (role != SWARM_PAYCYCLE_ROLE_CHANNEL && role != SWARM_PAYCYCLE_ROLE_ESCROW) {
        err = SWARM_PAYCYCLE_COLLATERAL;
        return false;
    }
    const auto it = m_rows.find(outpoint);
    if (it != m_rows.end()) {
        if (it->second.pool != pool) {
            err = SWARM_PAYCYCLE_OUTPOINT;
            return false;
        }
        if (it->second.role != role) {
            err = SWARM_PAYCYCLE_COLLATERAL_REUSE;
            return false;
        }
        err = SWARM_PAYCYCLE_REPLAY;
        return false;
    }
    if (role == SWARM_PAYCYCLE_ROLE_CHANNEL && !pools.Credit(pool, atoms)) {
        err = SWARM_PAYCYCLE_COLLATERAL;
        return false;
    }
    Row row;
    row.pool = pool;
    row.role = role;
    row.atoms = atoms;
    m_rows.emplace(outpoint, std::move(row));
    err.clear();
    return true;
}

std::string SwarmPayCollateral::pool(const std::string& outpoint) const
{
    const auto it = m_rows.find(outpoint);
    if (it == m_rows.end()) return {};
    return it->second.pool;
}

std::string SwarmPayCollateral::role(const std::string& outpoint) const
{
    const auto it = m_rows.find(outpoint);
    if (it == m_rows.end()) return {};
    return it->second.role;
}

int64_t SwarmPayCollateral::atoms(const std::string& outpoint) const
{
    const auto it = m_rows.find(outpoint);
    if (it == m_rows.end()) return 0;
    return it->second.atoms;
}

} // namespace modelnet
