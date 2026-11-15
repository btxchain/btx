// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ELECHOLD_H
#define BITCOIN_MODELNET_SWARM_ELECHOLD_H

#include <modelnet/swarm_elechold/atoms.h>
#include <modelnet/swarm_elechold/book.h>
#include <modelnet/swarm_elechold/quiet.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Electricity-cost plane.
 * A watt-hour measurement is not a BTX charge. No atoms move.
 *
 * Measure stores watt-hours when the count is at least 1. That call returns
 * true and clears err. watt_hours below 1 is MEASURE and stores nothing.
 * A second Measure of a count at least 1 is REPLAY and keeps the first
 * watt-hour count. MEASURE is decided before REPLAY.
 *
 * Charge always sets err to HELD and returns false. charged() stays
 * false. atoms_moved() stays 0. A charge before a measurement and a
 * charge after a measurement leave the watt-hour count unchanged and add
 * no atoms. atoms below 1 is still HELD.
 *
 * automatic_spend() stays "0". broadcast() stays false.
 * bytes_moved() stays 0. gpu() stays false.
 */
class SwarmElecHold {
public:
    /**
     * Measure one watt-hour count.
     * watt_hours below 1 is MEASURE and stores nothing.
     * watt_hours of 1 or more is stored and the call returns true.
     * A second Measure of a count at least 1 is REPLAY and keeps the
     * first watt-hour count.
     */
    bool Measure(int64_t watt_hours, std::string& err);

    /**
     * Always HELD. charged() stays false. atoms_moved() stays 0.
     * The stored watt-hour count is left as it was. atoms below 1 is still
     * HELD.
     */
    bool Charge(int64_t atoms, std::string& err) const;

    /** True when Measure stored a watt-hour count. */
    bool measured() const;

    /** The stored watt-hour count, or 0 when nothing is stored. */
    int64_t watt_hours() const;

    /** Stays false. A measurement is not a charge. */
    bool charged() const;

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
    SwarmElecHoldBook m_book;
    SwarmElecHoldAtoms m_atoms;
    SwarmElecHoldQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ELECHOLD_H
