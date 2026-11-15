// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSIGHASH_H
#define BTX_MODELNET_SWARM_NOTNOSIGHASH_H

#include <string>

namespace modelnet {

/**
 * A local note about one sighash. covers_outputs records whether the
 * sighash covers outputs. want_accept asks this note to accept it.
 *
 * A sighash that does not cover outputs is refused, and this note spends
 * nothing. accepted and spent stay false on every path.
 */
struct SwarmNotNoSighash {
    std::string sighash_id;
    bool covers_outputs{false};
    bool want_accept{false};
};

/**
 * Outcome of noting a sighash. accepted and spent stay false on every
 * path. A sighash that does not cover outputs is refused, and this note
 * spends nothing.
 */
struct SwarmNotNoSighashResult {
    std::string code;
    bool accepted{false};
    bool spent{false};
};

/**
 * Note a sighash without spending. Order, first match wins: an empty
 * sighash_id is SIGHASH. covers_outputs false is REFUSED even when
 * want_accept is false. want_accept is REFUSED. Otherwise the note is
 * NOTED and err is cleared. accepted and spent stay false on every path.
 * A sighash that does not cover outputs is refused, and this note spends
 * nothing.
 */
SwarmNotNoSighashResult SwarmNoteNotNoSighash(const SwarmNotNoSighash& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSIGHASH_H
