// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_H

#include <modelnet/swarm_schedwit/book.h>
#include <modelnet/swarm_schedwit/quiet.h>
#include <modelnet/swarm_schedwit/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Scheduler witness plane.
 * A witness is recorded and is not signed.
 *
 * Sign stores a non-empty witness and returns false. err is NOT_SIGNED.
 * signed_ok() stays false.
 * An empty witness is WITNESS and stores nothing.
 * A second Sign of the same witness is REPLAY and keeps the first.
 * WITNESS is decided before REPLAY. REPLAY is decided before NOT_SIGNED.
 *
 * atoms_moved() stays 0. automatic_spend() stays "0".
 * broadcast() stays false. bytes_moved() stays 0. gpu() stays false.
 * There is no method that sets signed_ok() true, arms a spend, or attaches a key.
 */
class SwarmSchedWitness {
public:
    /**
     * Record one witness.
     * An empty witness is WITNESS and stores nothing.
     * A non-empty witness is stored and the call returns false. err is NOT_SIGNED.
     * A second Sign of the same witness is REPLAY and keeps the first.
     * signed_ok() stays false.
     */
    bool Sign(const std::string& witness, std::string& err);

    /** True when Sign kept this witness. */
    bool kept(const std::string& witness) const;

    /** The kept witness, or empty when it was not stored. */
    std::string stored_witness(const std::string& witness) const;

    /** Number of kept witnesses. */
    std::size_t sign_count() const;

    /** Stays false. A recorded witness is not signed. */
    bool signed_ok() const;

    /** Stays 0. No atoms move. */
    int64_t atoms_moved() const;

    /** Stays "0". Nothing is spent. */
    std::string automatic_spend() const;

    /** Stays false. Nothing is broadcast. */
    bool broadcast() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

private:
    SwarmSchedWitnessBook m_book;
    SwarmSchedWitnessQuiet m_quiet;
    SwarmSchedWitnessStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_H
