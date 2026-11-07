// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_H

#include <modelnet/swarm_disputestay/atoms.h>
#include <modelnet/swarm_disputestay/book.h>
#include <modelnet/swarm_disputestay/hold.h>
#include <modelnet/swarm_disputestay/quiet.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Dispute-hold plane.
 * A dispute can be opened and cannot be settled. No atoms move.
 *
 * Open stores a non-empty dispute id and returns true. That call clears err.
 * An empty dispute id is DISPUTE and stores nothing.
 * A second Open of the same id is REPLAY and keeps the first.
 * DISPUTE is decided before REPLAY.
 *
 * Settle returns false. An empty id is DISPUTE and stores nothing.
 * Every other id is HELD. An unknown id is not stored by Settle.
 * Atoms below 1 on a known id add nothing. Atoms at or above 1 are
 * still HELD and add nothing. settled() stays false. atoms_moved() stays 0.
 *
 * broadcast() stays false. mined() stays false.
 * bytes_moved() stays 0. automatic_spend() stays "0".
 */
class SwarmDisputeStay {
public:
    /**
     * Open one dispute id.
     * An empty id is DISPUTE and stores nothing.
     * A non-empty id is stored and the call returns true.
     * A second Open of the same id is REPLAY and keeps the first.
     */
    bool Open(const std::string& dispute, std::string& err);

    /**
     * Refuse to settle one dispute.
     * An empty id is DISPUTE and stores nothing.
     * Any other id is HELD. The call returns false.
     * settled() stays false. atoms_moved() stays 0.
     * An unknown id is not stored. Atoms below 1 on a known id add nothing.
     */
    bool Settle(const std::string& dispute, int64_t atoms, std::string& err) const;

    /** True when Open kept this dispute id. */
    bool opened(const std::string& dispute) const;

    /** The kept dispute id, or empty when it was not stored. */
    std::string stored_id(const std::string& dispute) const;

    /** Number of kept dispute ids. */
    std::size_t open_count() const;

    /** Stays false. An opened dispute is not settled. */
    bool settled() const;

    /** Stays 0. Nothing is paid. */
    int64_t atoms_moved() const;

    /** Always false. Nothing is broadcast. */
    bool broadcast() const;

    /** Always false. Nothing is mined. */
    bool mined() const;

    /** Always 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays the string "0". */
    std::string automatic_spend() const;

private:
    SwarmDisputeStayBook m_book;
    SwarmDisputeStayAtoms m_atoms;
    SwarmDisputeStayHold m_hold;
    SwarmDisputeStayQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_H
