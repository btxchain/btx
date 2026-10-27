// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTWITNESS_H
#define BTX_MODELNET_SWARM_NOTWITNESS_H

#include <string>

namespace modelnet {

/**
 * A local note that a node might verify a funding witness.
 * want_verify asks this note to treat the witness as verified.
 *
 * verified stays false on every path. A signature-size check is not an
 * interpreter-verified funding witness.
 */
struct SwarmNotWitness {
    std::string tx_id;
    bool want_verify{false};
};

/**
 * Outcome of noting an unverified funding witness. verified stays false on
 * every path: a signature-size check is not an interpreter-verified funding
 * witness.
 */
struct SwarmNotWitnessResult {
    std::string code;
    bool verified{false};
};

/**
 * Note that a signature-size check is not an interpreter-verified funding
 * witness. Order, first match wins: an empty tx_id is TX. want_verify is
 * UNVERIFIED. Otherwise the note is NOTED and err is clear.
 * verified stays false on every path.
 */
SwarmNotWitnessResult SwarmNoteNotWitness(const SwarmNotWitness& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTWITNESS_H
