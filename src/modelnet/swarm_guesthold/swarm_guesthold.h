// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GUESTHOLD_H
#define BITCOIN_MODELNET_SWARM_GUESTHOLD_H

#include <modelnet/swarm_guesthold/book.h>
#include <modelnet/swarm_guesthold/quiet.h>
#include <modelnet/swarm_guesthold/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Guest-agent hold plane.
 * A guest-agent check is recorded and does not pass or log in.
 *
 * Check stores a non-empty name and returns false. err is NOT_PASSED.
 * passed() stays false. logged_in() stays false.
 * An empty name is GUEST and stores nothing.
 * A second Check of the same name is REPLAY and keeps the first.
 * GUEST is decided before REPLAY. REPLAY is decided before NOT_PASSED.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 */
class SwarmGuestHold {
public:
    /**
     * Record one guest-agent check.
     * An empty name is GUEST and stores nothing.
     * A non-empty name is stored and the call returns false. err is NOT_PASSED.
     * A second Check of the same name is REPLAY and keeps the first.
     * passed() stays false. logged_in() stays false.
     */
    bool Check(const std::string& name, std::string& err);

    /** True when Check kept this name. */
    bool checked(const std::string& name) const;

    /** The kept name, or empty when it was not stored. */
    std::string stored_name(const std::string& name) const;

    /** Number of kept names. */
    std::size_t check_count() const;

    /** Stays false. A recorded check is not passed. */
    bool passed() const;

    /** Stays false. A recorded check does not log in. */
    bool logged_in() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmGuestHoldBook m_book;
    SwarmGuestHoldQuiet m_quiet;
    SwarmGuestHoldStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GUESTHOLD_H
