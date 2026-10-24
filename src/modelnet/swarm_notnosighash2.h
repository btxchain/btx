// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSIGHASH2_H
#define BTX_MODELNET_SWARM_NOTNOSIGHASH2_H

#include <string>

namespace modelnet {

/**
 * A local note about one sighash. tx_id names the transaction.
 * covers_outputs records whether the sighash covers outputs.
 * want_accept asks this note to accept it.
 *
 * A sighash that does not cover outputs is refused. accepted and spent
 * stay false on every path.
 */
struct SwarmNotNoSighash2 {
    std::string tx_id;
    bool covers_outputs{true};
    bool want_accept{false};
};

/**
 * Outcome of noting a sighash. accepted and spent stay false on every
 * path. A sighash that does not cover outputs is refused.
 */
struct SwarmNotNoSighash2Result {
    std::string code;
    bool accepted{false};
    bool spent{false};
};

/**
 * Note a sighash without accepting it. Order, first match wins: an
 * empty tx_id is TX. covers_outputs false is REFUSED even when
 * want_accept is false. want_accept is HELD. Otherwise the note is
 * NOTED and err is cleared. accepted and spent stay false on every
 * path. A sighash that does not cover outputs is refused.
 */
SwarmNotNoSighash2Result SwarmNoteNotNoSighash2(const SwarmNotNoSighash2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSIGHASH2_H
