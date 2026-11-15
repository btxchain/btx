// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LOGINHOLD_H
#define BITCOIN_MODELNET_SWARM_LOGINHOLD_H

#include <modelnet/swarm_loginhold/book.h>
#include <modelnet/swarm_loginhold/quiet.h>
#include <modelnet/swarm_loginhold/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Login hold plane.
 * A login request is recorded and does not log in.
 *
 * Request stores a non-empty name and returns false. err is HELD.
 * logged_in() stays false.
 * An empty name is LOGIN and stores nothing.
 * A second Request of the same name is REPLAY and keeps the first.
 * LOGIN is decided before REPLAY. REPLAY is decided before HELD.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 */
class SwarmLoginHold {
public:
    /**
     * Record one login request.
     * An empty name is LOGIN and stores nothing.
     * A non-empty name is stored and the call returns false. err is HELD.
     * A second Request of the same name is REPLAY and keeps the first.
     * logged_in() stays false.
     */
    bool Request(const std::string& name, std::string& err);

    /** True when Request kept this name. */
    bool requested(const std::string& name) const;

    /** The kept name, or empty when it was not stored. */
    std::string stored_name(const std::string& name) const;

    /** Number of kept names. */
    std::size_t request_count() const;

    /** Stays false. A recorded request is not logged in. */
    bool logged_in() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmLoginHoldBook m_book;
    SwarmLoginHoldQuiet m_quiet;
    SwarmLoginHoldStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LOGINHOLD_H
