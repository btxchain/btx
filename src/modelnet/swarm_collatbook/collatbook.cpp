// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_collatbook/collatbook.h>

#include <modelnet/swarm_collatbook/bucket.h>
#include <modelnet/swarm_collatbook/codes.h>
#include <modelnet/swarm_collatbook/merge.h>
#include <modelnet/swarm_collatbook/quiet.h>
#include <modelnet/swarm_collatbook/same.h>

namespace modelnet {

bool SwarmCollatBook::Reserve(const std::string& pool, const std::string& outpoint, const std::string& bucket, std::string& err)
{
    // An empty pool or outpoint is not a reservation. Atoms are not moved.
    if (pool.empty() || outpoint.empty()) {
        err = SWARM_COLLAT_COLLATERAL;
        return false;
    }
    if (!SwarmCollatAcceptBucket(bucket, err)) {
        return false;
    }

    std::string held_pool;
    std::string held_bucket;
    if (m_table.Find(outpoint, held_pool, held_bucket)) {
        if (held_pool == pool) {
            if (held_bucket == bucket) {
                // The same reservation again does not add a row.
                err = SWARM_COLLAT_REPLAY;
                return false;
            }
            // The same outpoint cannot be both escrow and collateral.
            err = SWARM_COLLAT_BOTH;
            return false;
        }
        // The first pool keeps the outpoint. The second reservation is not stored.
        return SwarmCollatRefuseSecond(m_same, held_pool, pool, outpoint, err);
    }

    if (!SwarmCollatNoteFirst(m_same, pool, outpoint, err)) {
        return false;
    }
    if (!m_table.Insert(pool, outpoint, bucket)) {
        err = SWARM_COLLAT_REUSE;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmCollatBook::Merge(std::string& err) const
{
    return SwarmCollatMerge(err);
}

bool SwarmCollatBook::broadcast() const
{
    return SwarmCollatBroadcast();
}

int64_t SwarmCollatBook::bytes_moved() const
{
    return SwarmCollatBytesMoved();
}

int64_t SwarmCollatBook::earned() const
{
    return SwarmCollatEarned();
}

int64_t SwarmCollatBook::rows() const
{
    return m_table.rows();
}

bool SwarmCollatBook::held(const std::string& outpoint) const
{
    return m_table.held(outpoint);
}

std::string SwarmCollatBook::winner(const std::string& outpoint) const
{
    std::string pool;
    std::string bucket;
    if (!m_table.Find(outpoint, pool, bucket)) {
        return {};
    }
    return pool;
}

std::string SwarmCollatBook::bucket(const std::string& outpoint) const
{
    std::string pool;
    std::string held_bucket;
    if (!m_table.Find(outpoint, pool, held_bucket)) {
        return {};
    }
    return held_bucket;
}

std::string SwarmCollatBook::first_pool(const std::string& outpoint) const
{
    return m_same.FirstPool(outpoint);
}

} // namespace modelnet
