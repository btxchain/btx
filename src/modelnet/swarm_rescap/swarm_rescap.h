// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_H
#define BITCOIN_MODELNET_SWARM_RESCAP_H

#include <modelnet/swarm_rescap/book.h>
#include <modelnet/swarm_rescap/quiet.h>
#include <modelnet/swarm_rescap/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Resource cap plane.
 * A thread count is recorded and is not raised.
 *
 * Raise stores a count from 1 through 64 and returns false. err is CAPPED.
 * raised() stays false. cap_threads() stays 64.
 * threads below 1 is CAP and stores nothing.
 * threads above 64 is CAPPED and stores nothing.
 * A second Raise of the same stored count is REPLAY and keeps the first.
 * CAP is decided before the over-cap CAPPED. That CAPPED is decided
 * before REPLAY. REPLAY is decided before the stored CAPPED.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 */
class SwarmResCap {
public:
    /**
     * Record one thread count.
     * threads below 1 is CAP and stores nothing.
     * threads above 64 is CAPPED and stores nothing.
     * A count from 1 through 64 is stored and the call returns false.
     * err is CAPPED. raised() stays false.
     * A second Raise of the same count is REPLAY and keeps the first.
     */
    bool Raise(int64_t threads, std::string& err);

    /** True when Raise kept this thread count. */
    bool stored(int64_t threads) const;

    /** The kept thread count, or 0 when it was not stored. */
    int64_t stored_threads(int64_t threads) const;

    /** Number of kept thread counts. */
    std::size_t raise_count() const;

    /** Stays false. A recorded count is not raised. */
    bool raised() const;

    /** Stays 64. Nothing changes the cap. */
    int64_t cap_threads() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmResCapBook m_book;
    SwarmResCapQuiet m_quiet;
    SwarmResCapStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_H
