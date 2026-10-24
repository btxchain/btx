// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFOURBAL_H
#define BTX_MODELNET_SWARM_NOTFOURBAL_H

#include <string>

namespace modelnet {

/**
 * A local note about four balances. want_merge asks this note to merge
 * them.
 *
 * The four balances stay separate. merged stays false on every path.
 */
struct SwarmNotFourBal {
    std::string ledger_id;
    bool want_merge{false};
};

/**
 * Outcome of noting four balances. merged stays false on every path:
 * the four balances stay separate.
 */
struct SwarmNotFourBalResult {
    std::string code;
    bool merged{false};
};

/**
 * Note four balances without merging them.
 * Order, first match wins: an empty ledger_id is LEDGER. want_merge is
 * SEPARATE. Otherwise the note is NOTED and err is clear.
 * merged stays false on every path. The four balances stay separate.
 */
SwarmNotFourBalResult SwarmNoteNotFourBal(const SwarmNotFourBal& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFOURBAL_H
