// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYCYCLE_COLLATERAL_H
#define BITCOIN_MODELNET_SWARM_PAYCYCLE_COLLATERAL_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

class SwarmPayPools;

/**
 * One outpoint funds one pool, in one role.
 * Channel reserve adds atoms to that pool's in-memory balance.
 * Escrow reserve does not. The same pool cannot use the outpoint as both roles.
 * A second pool cannot take an outpoint the first pool already holds.
 */
class SwarmPayCollateral {
public:
    bool Reserve(SwarmPayPools& pools, const std::string& pool, const std::string& outpoint, int64_t atoms,
                 const std::string& role, std::string& err);

    std::string pool(const std::string& outpoint) const;
    std::string role(const std::string& outpoint) const;
    int64_t atoms(const std::string& outpoint) const;

private:
    struct Row {
        std::string pool;
        std::string role;
        int64_t atoms{0};
    };

    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYCYCLE_COLLATERAL_H
