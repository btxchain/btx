// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_SWARM_HOLDROT_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_SWARM_HOLDROT_H

#include <modelnet/swarm_holdrot/book.h>
#include <modelnet/swarm_holdrot/quiet.h>
#include <modelnet/swarm_holdrot/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Holdout rotate plane.
 * A holdout is recorded and does not rotate.
 *
 * Rotate stores a non-empty holdout and returns false. err is NOT_ROTATING.
 * rotated() stays false.
 * An empty holdout is HOLDOUT and stores nothing.
 * A second Rotate of the same holdout is REPLAY and keeps the first.
 * HOLDOUT is decided before REPLAY. REPLAY is decided before NOT_ROTATING.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 * There is no method that sets rotated() true or turns a holdout into a rotating set.
 */
class SwarmHoldoutRotate {
public:
    /**
     * Record one holdout.
     * An empty holdout is HOLDOUT and stores nothing.
     * A non-empty holdout is stored and the call returns false. err is NOT_ROTATING.
     * A second Rotate of the same holdout is REPLAY and keeps the first.
     * rotated() stays false.
     */
    bool Rotate(const std::string& holdout, std::string& err);

    /** True when Rotate kept this holdout. */
    bool held(const std::string& holdout) const;

    /** The kept holdout, or empty when it was not stored. */
    std::string stored_holdout(const std::string& holdout) const;

    /** Number of kept holdouts. */
    std::size_t holdout_count() const;

    /** Stays false. A recorded holdout is not rotating. */
    bool rotated() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmHoldoutRotateBook m_book;
    SwarmHoldoutRotateQuiet m_quiet;
    SwarmHoldoutRotateStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_SWARM_HOLDROT_H
