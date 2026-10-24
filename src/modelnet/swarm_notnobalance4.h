// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBALANCE4_H
#define BTX_MODELNET_SWARM_NOTNOBALANCE4_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one ledger. ledger_id names the ledger.
 * want_merge asks this note to merge.
 *
 * Four balances stay separate. This note merges nothing.
 * merged stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoBalance4 {
    std::string ledger_id;
    bool want_merge{false};
};

/**
 * Outcome of noting a ledger. merged stays false and atoms stays 0
 * on every path. Four balances stay separate. This note merges nothing.
 */
struct SwarmNotNoBalance4Result {
    std::string code;
    bool merged{false};
    int64_t atoms{0};
};

/**
 * Note a ledger without merging balances. Order, first match wins:
 * an empty ledger_id is LEDGER. want_merge is HELD. Otherwise the note
 * is NOTED and err is cleared. merged stays false and atoms stays 0 on
 * every path. Four balances stay separate. This note merges nothing.
 */
SwarmNotNoBalance4Result SwarmNoteNotNoBalance4(const SwarmNotNoBalance4& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBALANCE4_H
