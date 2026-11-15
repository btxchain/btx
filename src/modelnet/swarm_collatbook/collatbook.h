// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_COLLATBOOK_H
#define BITCOIN_MODELNET_SWARM_COLLATBOOK_H

#include <modelnet/swarm_collatbook/table.h>
#include <modelnet/swarm_paymesh.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-memory collateral reservation. Reserve records one outpoint for
 * the first pool that asks. Atoms are not moved. The same atoms are
 * never both escrow and collateral.
 * Merge does not run. Nothing is broadcast. bytes_moved stays 0.
 * earned stays 0.
 */
class SwarmCollatBook {
public:
    /**
     * Record a reservation of one outpoint. The atoms stay where they are.
     * Empty pool or empty outpoint is COLLATERAL and stores nothing.
     * A bucket other than "escrow" or "collateral" is BUCKET and stores nothing.
     * The same pool, outpoint, and bucket again is REPLAY and does not
     * add a second row.
     * The same pool and outpoint with the other bucket is BOTH and stores nothing.
     * A different pool for an outpoint already reserved calls SwarmSameCollateral
     * and returns that error, or COLLATERAL_REUSE when the helper sets none.
     * The second reservation is not stored. The first pool keeps the outpoint.
     */
    bool Reserve(const std::string& pool, const std::string& outpoint, const std::string& bucket, std::string& err);

    /** Sets err to NOT_MERGED. No row changes. */
    bool Merge(std::string& err) const;

    /** Always false. Nothing is broadcast. */
    bool broadcast() const;

    /** Always 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Always 0. A reservation does not earn. */
    int64_t earned() const;

    /** Stored reservations. A refusal does not change this. */
    int64_t rows() const;

    /** True when Reserve stored this outpoint. */
    bool held(const std::string& outpoint) const;

    /** Pool that holds this outpoint, or empty when it is not reserved. */
    std::string winner(const std::string& outpoint) const;

    /** Bucket stored for this outpoint, or empty when it is not reserved. */
    std::string bucket(const std::string& outpoint) const;

    /**
     * Pool SwarmSameCollateral recorded for this outpoint.
     * Empty when this book has not noted the outpoint.
     */
    std::string first_pool(const std::string& outpoint) const;

private:
    SwarmCollatTable m_table;
    SwarmCollateralBook m_same;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_COLLATBOOK_H
