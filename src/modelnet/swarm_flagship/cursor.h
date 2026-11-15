// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_CURSOR_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_CURSOR_H

#include <modelnet/swarm_flagship/ledger.h>
#include <modelnet/swarm_flagship/quiet.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process flagship cursor.
 * Records evidence ids for the thirteen flagship stages, in order:
 * acquire, join, coordinate, accelerate, experience, train, evolve,
 * evaluate, graduate, adopt, pay, recover, repeat.
 *
 * This plane does not run a stage, mark a stage passed, launch a
 * process, move bytes, or spend.
 *
 * Record stores an evidence id or stores nothing. First match wins.
 * A stage name outside the list is STAGE and stores nothing.
 * Empty evidence is EVIDENCE and stores nothing.
 * Any earlier stage with no stored evidence is ORDER and stores nothing.
 * A second record of the same stage and the same evidence is REPLAY
 * and keeps the first. A second record of the same stage with different
 * evidence is CONFLICT and keeps the first. Otherwise the evidence is
 * stored and the call returns true. passed() stays false.
 *
 * Pass refuses. A stage name outside the list is STAGE. Any listed
 * stage, recorded or not, returns false with NOT_PASSED. Recording
 * evidence does not make Pass succeed. passed(), gpu_passed(),
 * windows_passed(), and pay_passed() stay false.
 *
 * Rollback clears evidence. A stage name outside the list is STAGE and
 * deletes nothing. A listed stage clears that stage and every later
 * stage. Earlier stages stay. The call returns true. passed() stays false.
 *
 * passed(), gpu_passed(), windows_passed(), and pay_passed() stay false.
 * launched(), gpu(), and broadcast() stay false. bytes_moved() stays 0.
 * atoms_moved() stays 0. automatic_spend() stays "0". There is no method
 * that sets any of those.
 */
class SwarmFlagshipCursor {
public:
    bool Record(const std::string& stage, const std::string& evidence, std::string& err);
    bool Pass(const std::string& stage, std::string& err) const;
    bool Rollback(const std::string& stage, std::string& err);

    bool recorded(const std::string& stage) const;
    std::string evidence(const std::string& stage) const;

    /** The first stage with no evidence, or empty when all thirteen are recorded. */
    std::string next_stage() const;

    bool passed() const;
    bool gpu_passed() const;
    bool windows_passed() const;
    bool pay_passed() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    std::uint64_t bytes_moved() const;
    std::uint64_t atoms_moved() const;
    std::string automatic_spend() const;

private:
    SwarmFlagshipLedger m_ledger;
    SwarmFlagshipQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_CURSOR_H
