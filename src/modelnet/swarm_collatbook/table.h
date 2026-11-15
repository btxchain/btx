// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_COLLATBOOK_TABLE_H
#define BITCOIN_MODELNET_SWARM_COLLATBOOK_TABLE_H

#include <modelnet/swarm_collatbook/row.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * One row per outpoint. Insert does not replace a row and does not
 * add a second row for an outpoint that is already present.
 */
class SwarmCollatTable {
public:
    /** True when this outpoint has a stored reservation. */
    bool held(const std::string& outpoint) const;

    /**
     * On success, pool and bucket are the stored reservation.
     * An unknown outpoint returns false and leaves both unchanged.
     */
    bool Find(const std::string& outpoint, std::string& pool, std::string& bucket) const;

    /**
     * Store the first reservation of this outpoint.
     * Empty pool, empty outpoint, empty bucket, or an outpoint that
     * already has a row returns false and leaves the table unchanged.
     */
    bool Insert(const std::string& pool, const std::string& outpoint, const std::string& bucket);

    /** Number of stored reservations. */
    int64_t rows() const;

private:
    std::map<std::string, SwarmCollatRow> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_COLLATBOOK_TABLE_H
