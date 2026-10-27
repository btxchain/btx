// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FUNDSIGN_H
#define BTX_MODELNET_SWARM_FUNDSIGN_H

#include <string>

namespace modelnet {

/**
 * A local note of a requested funding witness.
 * scheduler_id names the scheduler. scheduler_signs asks this note to
 * treat the scheduler as the signer. want_broadcast asks this note to
 * broadcast the witness.
 *
 * signed_witness and broadcast stay false on every path. Nothing is
 * signed and nothing is broadcast. No hostnames or IPs are used.
 */
struct SwarmFundingWitness {
    std::string scheduler_id;
    bool scheduler_signs{false};
    bool want_broadcast{false};
};

/**
 * Outcome of noting a funding witness. signed_witness and broadcast stay
 * false: nothing is signed and nothing is broadcast.
 */
struct SwarmFundingWitnessResult {
    bool signed_witness{false};
    bool broadcast{false};
    std::string code;
};

/**
 * Note a funding witness without signing or broadcasting it.
 * Order, first match wins:
 * an empty scheduler_id is WITNESS.
 * scheduler_signs is SIGN_REFUSED, including when want_broadcast is true.
 * The scheduler does not sign a funding witness.
 * want_broadcast is BROADCAST_FORBIDDEN.
 * Otherwise the note is NOTED and err is cleared.
 * signed_witness and broadcast stay false. Nothing is signed and nothing
 * is broadcast.
 */
SwarmFundingWitnessResult SwarmNoteFundingWitness(const SwarmFundingWitness& witness, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FUNDSIGN_H
