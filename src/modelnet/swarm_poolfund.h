// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_POOLFUND_H
#define BTX_MODELNET_SWARM_POOLFUND_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory record of whether a named pool has been funded.
 *
 * Create stores the pool with atoms 0 and funded false. Fund sets the
 * atom count once. An unfunded pool is not advertised as holding money:
 * Advertised is false and atoms() is 0 until a successful Fund.
 *
 * This ledger does not broadcast, spend, spawn a child process, open a
 * network connection, or use a hostname or IP.
 */
class SwarmPoolFund {
public:
    /**
     * An empty pool is POOL and stores nothing. A second Create for the
     * same pool is REPLAY and leaves the stored row. Success stores atoms
     * 0 and funded false, clears err, and returns true.
     */
    bool Create(const std::string& pool, std::string& err);

    /**
     * An unknown pool is POOL. atoms < 1 is ATOMS and leaves the row.
     * A pool that is already funded is REPLAY and leaves the atoms.
     * Success sets atoms and funded true, clears err, and returns true.
     */
    bool Fund(const std::string& pool, int64_t atoms, std::string& err);

    /** True only when the pool exists and funded is true. */
    bool Advertised(const std::string& pool) const;

    /** 0 when the pool is unknown or unfunded. */
    int64_t atoms(const std::string& pool) const;

private:
    struct Row {
        int64_t atoms{0};
        bool funded{false};
    };

    std::map<std::string, Row> m_pools;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_POOLFUND_H
