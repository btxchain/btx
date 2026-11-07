// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_H

#include <modelnet/swarm_gradhold/book.h>
#include <modelnet/swarm_gradhold/quiet.h>
#include <modelnet/swarm_gradhold/seal.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Gradient-hold plane.
 * A gradient update can be recorded and cannot be exported. No bytes move.
 *
 * Offer stores a non-empty update id and returns true. That call clears err.
 * An empty update id is UPDATE and stores nothing.
 * A second Offer of the same id is REPLAY and keeps the first.
 * UPDATE is decided before REPLAY.
 *
 * Export of an empty id is UPDATE and stores nothing.
 * Export of any other id, known or unknown, is NOT_EXPORTED and returns
 * false. An unknown id is not stored by Export. exported() stays false.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 */
class SwarmGradHold {
public:
    /**
     * Record one update id.
     * An empty id is UPDATE and stores nothing.
     * A non-empty id is stored and the call returns true.
     * A second Offer of the same id is REPLAY and keeps the first.
     */
    bool Offer(const std::string& update_id, std::string& err);

    /**
     * Refuse to export one update id.
     * An empty id is UPDATE and stores nothing.
     * Any other id is NOT_EXPORTED. The call returns false.
     * exported() stays false. An unknown id is not stored.
     */
    bool Export(const std::string& update_id, std::string& err);

    /** True when Offer kept this update id. */
    bool offered(const std::string& update_id) const;

    /** The kept update id, or empty when it was not stored. */
    std::string stored_id(const std::string& update_id) const;

    /** Number of kept update ids. */
    std::size_t offer_count() const;

    /** Stays false. A recorded update is not exported. */
    bool exported() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmGradHoldBook m_book;
    SwarmGradHoldQuiet m_quiet;
    SwarmGradHoldSeal m_seal;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_H
