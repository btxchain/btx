// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PASSHOLD_H
#define BITCOIN_MODELNET_SWARM_PASSHOLD_H

#include <modelnet/swarm_passhold/book.h>
#include <modelnet/swarm_passhold/quiet.h>
#include <modelnet/swarm_passhold/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * GPU passthrough hold plane.
 * A GPU passthrough request is recorded and does not start.
 *
 * Request stores a non-empty name and returns false. err is NOT_STARTED.
 * started() stays false. passed() stays false.
 * An empty name is PASSTHROUGH and stores nothing.
 * A second Request of the same name is REPLAY and keeps the first.
 * PASSTHROUGH is decided before REPLAY. REPLAY is decided before NOT_STARTED.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 */
class SwarmPassHold {
public:
    /**
     * Record one GPU passthrough request.
     * An empty name is PASSTHROUGH and stores nothing.
     * A non-empty name is stored and the call returns false. err is NOT_STARTED.
     * A second Request of the same name is REPLAY and keeps the first.
     * started() stays false. passed() stays false.
     */
    bool Request(const std::string& name, std::string& err);

    /** True when Request kept this name. */
    bool requested(const std::string& name) const;

    /** The kept name, or empty when it was not stored. */
    std::string stored_name(const std::string& name) const;

    /** Number of kept names. */
    std::size_t request_count() const;

    /** Stays false. A recorded request is not started. */
    bool started() const;

    /** Stays false. A recorded request is not passed. */
    bool passed() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmPassHoldBook m_book;
    SwarmPassHoldQuiet m_quiet;
    SwarmPassHoldStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PASSHOLD_H
