// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_RECORD_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One recorded witness.
 * The record holds the witness only. signed_ok stays false.
 * atoms_moved stays 0. automatic_spend stays "0".
 * broadcast stays false. bytes_moved stays 0. gpu stays false.
 * Make is the only writer of those fields. There is no setter,
 * no method that marks the witness signed, no spend arm, and no key.
 */
class SwarmSchedWitnessRecord {
public:
    static SwarmSchedWitnessRecord Make(const std::string& witness);

    const std::string& witness() const { return m_witness; }
    bool signed_ok() const { return m_signed_ok; }
    int64_t atoms_moved() const { return m_atoms_moved; }
    const std::string& automatic_spend() const { return m_automatic_spend; }
    bool broadcast() const { return m_broadcast; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool gpu() const { return m_gpu; }

private:
    std::string m_witness;
    bool m_signed_ok{false};
    int64_t m_atoms_moved{0};
    std::string m_automatic_spend{"0"};
    bool m_broadcast{false};
    int64_t m_bytes_moved{0};
    bool m_gpu{false};
};

/**
 * The witness is non-empty, the witness is not signed, no atoms moved,
 * automatic spend stays "0", nothing is broadcast, no bytes moved,
 * and the gpu is idle.
 */
bool SwarmSchedWitnessRecordUsable(const SwarmSchedWitnessRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_RECORD_H
