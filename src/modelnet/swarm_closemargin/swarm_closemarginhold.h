// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGINHOLD_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGINHOLD_H

#include <modelnet/swarm_closemargin/book.h>
#include <modelnet/swarm_closemargin/quiet.h>
#include <modelnet/swarm_closemargin/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Close-margin hold plane.
 * A shrink request is recorded and does not shrink the margin.
 *
 * Shrink stores a block count of 160 and returns false. err is HELD.
 * margin_blocks() stays 160. shrunk() stays false.
 * A block count other than 160 is MARGIN and stores nothing.
 * A second Shrink of 160 is REPLAY and keeps the first.
 * MARGIN is decided before REPLAY. REPLAY is decided before HELD.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 * mined() stays false.
 */
class SwarmCloseMarginHold {
public:
    /**
     * Record one shrink request.
     * A count other than 160 is MARGIN and stores nothing.
     * A count of 160 is stored and the call returns false. err is HELD.
     * A second Shrink of 160 is REPLAY and keeps the first.
     * margin_blocks() stays 160. shrunk() stays false.
     */
    bool Shrink(int64_t blocks, std::string& err);

    /** True when Shrink kept this block count. */
    bool stored(int64_t blocks) const;

    /** The kept block count, or 0 when it was not stored. */
    int64_t stored_blocks(int64_t blocks) const;

    /** Number of kept requests. */
    std::size_t request_count() const;

    /** Stays 160. The close margin does not change. */
    int64_t margin_blocks() const;

    /** Stays false. A recorded request does not shrink the margin. */
    bool shrunk() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

    /** Stays false. Nothing is mined. */
    bool mined() const;

private:
    SwarmCloseMarginHoldBook m_book;
    SwarmCloseMarginHoldQuiet m_quiet;
    SwarmCloseMarginHoldStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGINHOLD_H
