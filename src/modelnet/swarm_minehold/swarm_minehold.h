// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MINEHOLD_H
#define BITCOIN_MODELNET_SWARM_MINEHOLD_H

#include <modelnet/swarm_minehold/book.h>
#include <modelnet/swarm_minehold/mine.h>
#include <modelnet/swarm_minehold/quiet.h>
#include <modelnet/swarm_minehold/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Mine-hold plane.
 * A mine request is recorded and does not mine.
 *
 * Request stores a non-empty name and returns false. err is HELD.
 * mined() stays false. blocks() stays 0.
 * An empty name is MINE and stores nothing.
 * A second Request of the same name is REPLAY and keeps the first.
 * MINE is decided before REPLAY. REPLAY is decided before HELD.
 *
 * bytes_moved() stays 0. broadcast() stays false. gpu() stays false.
 */
class SwarmMineHold {
public:
    /**
     * Record one mine request.
     * An empty name is MINE and stores nothing.
     * A non-empty name is stored and the call returns false. err is HELD.
     * A second Request of the same name is REPLAY and keeps the first.
     * mined() stays false. blocks() stays 0.
     */
    bool Request(const std::string& name, std::string& err);

    /** True when Request kept this name. */
    bool requested(const std::string& name) const;

    /** The kept name, or empty when it was not stored. */
    std::string stored_name(const std::string& name) const;

    /** Number of kept names. */
    std::size_t request_count() const;

    /** Stays false. A recorded request is not mined. */
    bool mined() const;

    /** Stays 0. Nothing is mined. */
    int64_t blocks() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. Nothing is broadcast. */
    bool broadcast() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

private:
    SwarmMineHoldBook m_book;
    SwarmMineHoldMine m_mine;
    SwarmMineHoldQuiet m_quiet;
    SwarmMineHoldStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MINEHOLD_H
