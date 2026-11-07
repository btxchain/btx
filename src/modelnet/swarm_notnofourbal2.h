// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFOURBAL2_H
#define BTX_MODELNET_SWARM_NOTNOFOURBAL2_H

#include <string>

namespace modelnet {

/**
 * A local note about four balances. ledger_id names the ledger.
 * want_merge asks this note to merge them.
 *
 * Four balances stay separate. merged stays false on every path.
 */
struct SwarmNotNoFourBal2 {
    std::string ledger_id;
    bool want_merge{false};
};

/**
 * Outcome of noting four balances. merged stays false on every path.
 * Four balances stay separate.
 */
struct SwarmNotNoFourBal2Result {
    std::string code;
    bool merged{false};
};

/**
 * Note four balances without merging them. Order, first match wins:
 * an empty ledger_id is LEDGER. want_merge is HELD. Otherwise the note
 * is NOTED and err is cleared. merged stays false on every path.
 * Four balances stay separate.
 */
SwarmNotNoFourBal2Result SwarmNoteNotNoFourBal2(const SwarmNotNoFourBal2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFOURBAL2_H
