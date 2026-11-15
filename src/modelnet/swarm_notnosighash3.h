// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSIGHASH3_H
#define BTX_MODELNET_SWARM_NOTNOSIGHASH3_H

#include <string>

namespace modelnet {

/**
 * A local note about one sighash. tx_id names the transaction.
 * skips_outputs records whether the sighash skips outputs.
 * want_sign asks this note to sign it.
 *
 * A sighash that skips outputs is refused. signed_tx and spent stay
 * false on every path.
 */
struct SwarmNotNoSighash3 {
    std::string tx_id;
    bool skips_outputs{false};
    bool want_sign{false};
};

/**
 * Outcome of noting a sighash. signed_tx and spent stay false on every
 * path. A sighash that skips outputs is refused.
 */
struct SwarmNotNoSighash3Result {
    std::string code;
    bool signed_tx{false};
    bool spent{false};
};

/**
 * Note a sighash without signing it. Order, first match wins: an empty
 * tx_id is TX. skips_outputs true is REFUSED even when want_sign is
 * false. want_sign is HELD. Otherwise the note is NOTED and err is
 * cleared. signed_tx and spent stay false on every path. A sighash
 * that skips outputs is refused.
 */
SwarmNotNoSighash3Result SwarmNoteNotNoSighash3(const SwarmNotNoSighash3& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSIGHASH3_H
