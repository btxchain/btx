// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWITNESS2_H
#define BTX_MODELNET_SWARM_NOTNOWITNESS2_H

#include <string>

namespace modelnet {

/**
 * A local note about a scheduler. want_sign asks this note to sign a
 * funding witness.
 *
 * The scheduler does not sign a funding witness. signed_witness and
 * spent stay false on every path.
 */
struct SwarmNotNoWitness2 {
    std::string tx_id;
    bool scheduler{false};
    bool want_sign{false};
};

/**
 * Outcome of noting a scheduler. signed_witness and spent stay false on
 * every path. The scheduler does not sign a funding witness.
 */
struct SwarmNotNoWitness2Result {
    std::string code;
    bool signed_witness{false};
    bool spent{false};
};

/**
 * Note a scheduler without signing a funding witness. This note signs
 * nothing and spends nothing. Order, first match wins:
 * 1. An empty tx_id is TX. signed_witness stays false, spent stays
 *    false, and err is TX.
 * 2. If scheduler is true, the note is NOT_SIGNED even when want_sign
 *    is false. signed_witness stays false, spent stays false, and err
 *    is NOT_SIGNED.
 * 3. want_sign is HELD. signed_witness stays false, spent stays false,
 *    and err is HELD.
 * 4. Otherwise the note is NOTED and err is cleared. signed_witness
 *    stays false and spent stays false.
 * signed_witness and spent stay false on every path. The scheduler
 * does not sign a funding witness.
 */
SwarmNotNoWitness2Result SwarmNoteNotNoWitness2(const SwarmNotNoWitness2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWITNESS2_H
