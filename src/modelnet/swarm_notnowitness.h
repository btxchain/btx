// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWITNESS_H
#define BTX_MODELNET_SWARM_NOTNOWITNESS_H

#include <string>

namespace modelnet {

/**
 * A local note about a scheduler. want_sign asks this note to sign a funding
 * witness.
 *
 * The scheduler does not sign a funding witness.
 * signed_witness and broadcast stay false on every path.
 */
struct SwarmNotNoWitness {
    std::string scheduler_id;
    bool want_sign{false};
};

/**
 * Outcome of noting a scheduler. signed_witness and broadcast stay false on
 * every path. The scheduler does not sign a funding witness.
 */
struct SwarmNotNoWitnessResult {
    std::string code;
    bool signed_witness{false};
    bool broadcast{false};
};

/**
 * Note a scheduler without signing a funding witness.
 * Order, first match wins: an empty scheduler_id is SCHEDULER. want_sign is
 * NO_KEY. Otherwise the note is NOTED and err is clear.
 * signed_witness and broadcast stay false on every path.
 * The scheduler does not sign a funding witness.
 */
SwarmNotNoWitnessResult SwarmNoteNotNoWitness(const SwarmNotNoWitness& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWITNESS_H
