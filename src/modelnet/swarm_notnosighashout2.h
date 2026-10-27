// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSIGHASHOUT2_H
#define BTX_MODELNET_SWARM_NOTNOSIGHASHOUT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one sighash. tx_id names the transaction.
 * skip_outputs records whether the sighash skips outputs.
 * want_sign asks this note to sign it.
 *
 * A sighash that skips outputs signs nothing.
 */
struct SwarmNotNoSighashOut2 {
    std::string tx_id;
    bool skip_outputs{false};
    bool want_sign{false};
};

/**
 * Outcome of noting a sighash. signed_ok stays false on every path.
 * A sighash that skips outputs signs nothing.
 */
struct SwarmNotNoSighashOut2Result {
    std::string code;
    bool signed_ok{false};
};

/**
 * Note a sighash without signing it. Order, first match wins: an empty
 * tx_id is TX. skip_outputs true is NOT_SIGNED even when want_sign is
 * false. want_sign is HELD. Otherwise the note is NOTED and err is
 * cleared. signed_ok stays false on every path. A sighash that skips
 * outputs signs nothing.
 */
SwarmNotNoSighashOut2Result SwarmNoteNotNoSighashOut2(const SwarmNotNoSighashOut2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSIGHASHOUT2_H
