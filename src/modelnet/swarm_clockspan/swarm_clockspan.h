// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_H

#include <modelnet/swarm_clockspan/book.h>
#include <modelnet/swarm_clockspan/mine.h>
#include <modelnet/swarm_clockspan/quiet.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Block-spacing plane.
 * A 90-second block spacing is not a wall-clock deadline. Nothing is mined.
 *
 * Note stores a spacing only when seconds is 90. That call returns true
 * and clears err. seconds below 1 is RANGE and stores nothing. Any other
 * positive seconds is SPACING and stores nothing. A second Note of 90 is
 * REPLAY and keeps the first spacing. RANGE and SPACING are decided
 * before REPLAY.
 *
 * ClaimDeadline always sets err to NOT_DEADLINE and returns false.
 * mined() stays false. blocks() stays 0. The stored spacing stays 90
 * when one was stored, and stays 0 when none was stored.
 * bytes_moved() stays 0. broadcast() stays false.
 */
class SwarmClockSpan {
public:
    /**
     * Note one spacing in seconds.
     * seconds below 1 is RANGE and stores nothing.
     * seconds of 90 is stored and the call returns true.
     * Any other positive seconds is SPACING and stores nothing.
     * A second Note of 90 is REPLAY and keeps the first spacing.
     */
    bool Note(int64_t seconds, std::string& err);

    /**
     * Always NOT_DEADLINE. mined() stays false. blocks() stays 0.
     * The stored spacing is left as it was.
     */
    bool ClaimDeadline(std::string& err);

    /** True when Note stored the 90-second spacing. */
    bool noted() const;

    /** 90 when a spacing was stored, otherwise 0. */
    int64_t spacing() const;

    /** Stays false. Nothing is mined. */
    bool mined() const;

    /** Stays 0. Nothing is mined. */
    int64_t blocks() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. Nothing is broadcast. */
    bool broadcast() const;

private:
    SwarmClockSpanBook m_book;
    SwarmClockSpanMine m_mine;
    SwarmClockSpanQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_H
