// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FOURBOOK_H
#define BTX_MODELNET_SWARM_FOURBOOK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Four local atom buckets: escrow, collateral, earned, and fees.
 * Credit adds atoms to exactly one bucket. Merge never combines them.
 * This book does not broadcast, spend, spawn a child process, open a
 * network connection, or use a hostname or IP.
 */
class SwarmFourBook {
public:
    /**
     * bucket must be escrow, collateral, earned, or fees; otherwise BUCKET.
     * atoms < 1 is ATOMS. A sum that would overflow int64_t is ATOMS and
     * leaves the bucket unchanged. Success adds atoms to that bucket only,
     * clears err, and returns true.
     */
    bool Credit(const std::string& bucket, int64_t atoms, std::string& err);

    /** Always false. err is NOT_MERGED. Every bucket stays unchanged. */
    bool Merge(std::string& err);

    /** 0 when bucket is not one of the four. */
    int64_t Balance(const std::string& bucket) const;

private:
    int64_t* Slot(const std::string& bucket);
    const int64_t* Slot(const std::string& bucket) const;

    int64_t m_escrow{0};
    int64_t m_collateral{0};
    int64_t m_earned{0};
    int64_t m_fees{0};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FOURBOOK_H
