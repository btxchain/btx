// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_BOOK_H
#define BITCOIN_MODELNET_SWARM_RESCAP_BOOK_H

#include <modelnet/swarm_rescap/record.h>

#include <cstddef>
#include <cstdint>
#include <map>

namespace modelnet {

/**
 * Thread counts recorded by Raise, keyed by the count.
 * store refuses a count below 1, a count above 64, and a count already
 * present. A refused store leaves the first count in place.
 * There is no method that raises a record, moves bytes, marks the gpu
 * busy, marks the record launched, or changes the cap away from 64.
 */
class SwarmResCapBook {
public:
    bool contains(int64_t threads) const;
    int64_t stored_threads(int64_t threads) const;
    std::size_t size() const;

    /** True when any kept record is raised. None are. */
    bool raised() const;

    /** Sum of bytes on every kept record. Each record is built with 0. */
    int64_t bytes_moved() const;

    /** True when any kept record marks the gpu. None do. */
    bool gpu() const;

    /** True when any kept record is marked launched. None are. */
    bool launched() const;

    /**
     * Record threads.
     * Refuses a count outside 1 through 64 and a count already present.
     * On refusal the book is unchanged.
     */
    bool store(int64_t threads);

private:
    std::map<int64_t, SwarmResCapRecord> m_raises;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_BOOK_H
