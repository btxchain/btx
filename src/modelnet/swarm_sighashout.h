// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SIGHASHOUT_H
#define BTX_MODELNET_SWARM_SIGHASHOUT_H

#include <string>

namespace modelnet {

/**
 * A local note of a sighash that must cover outputs.
 * tx_id names the transaction. covers_outputs is true only when the sighash
 * commits to the outputs. want_sign asks this note to sign.
 *
 * signed_ok stays false on every path. A sighash that skips outputs is refused.
 */
struct SwarmSighashOut {
    std::string tx_id;
    bool covers_outputs{false};
    bool want_sign{false};
};

/**
 * Outcome of noting a sighash. signed_ok stays false: nothing is signed.
 */
struct SwarmSighashOutResult {
    std::string code;
    bool signed_ok{false};
};

/**
 * Note a sighash without signing it.
 * Order, first match wins:
 * an empty tx_id is TX.
 * covers_outputs false is NOT_SIGNED, even when want_sign is false.
 * A sighash that skips outputs is refused.
 * want_sign is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * signed_ok stays false.
 */
SwarmSighashOutResult SwarmNoteSighashOutputs(const SwarmSighashOut& tx, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SIGHASHOUT_H
