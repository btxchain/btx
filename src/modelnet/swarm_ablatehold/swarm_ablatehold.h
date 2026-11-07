// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ABLATEHOLD_H
#define BITCOIN_MODELNET_SWARM_ABLATEHOLD_H

#include <modelnet/swarm_ablatehold/book.h>
#include <modelnet/swarm_ablatehold/quiet.h>
#include <modelnet/swarm_ablatehold/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Ablation-hold plane.
 * An ablation publish request is recorded and does not publish.
 *
 * Request stores a non-empty name and returns false. err is HELD.
 * published() stays false.
 * An empty name is ABLATION and stores nothing.
 * A second Request of the same name is REPLAY and keeps the first.
 * ABLATION is decided before REPLAY. REPLAY is decided before HELD.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 */
class SwarmAblateHold {
public:
    /**
     * Record one ablation publish request.
     * An empty name is ABLATION and stores nothing.
     * A non-empty name is stored and the call returns false. err is HELD.
     * A second Request of the same name is REPLAY and keeps the first.
     * published() stays false.
     */
    bool Request(const std::string& name, std::string& err);

    /** True when Request kept this name. */
    bool requested(const std::string& name) const;

    /** The kept name, or empty when it was not stored. */
    std::string stored_name(const std::string& name) const;

    /** Number of kept names. */
    std::size_t request_count() const;

    /** Stays false. A recorded request is not published. */
    bool published() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmAblateHoldBook m_book;
    SwarmAblateHoldQuiet m_quiet;
    SwarmAblateHoldStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ABLATEHOLD_H
