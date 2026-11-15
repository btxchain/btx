// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBALANCE_H
#define BTX_MODELNET_SWARM_NOTNOBALANCE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one ledger. ledger_id names the ledger.
 * mixed_books marks books that must not be combined. want_combine asks
 * this note to combine them.
 *
 * The four balances stay separate. combined stays false and atoms stays
 * 0 on every path.
 */
struct SwarmNotNoBalance {
    std::string ledger_id;
    bool mixed_books{false};
    bool want_combine{false};
};

/**
 * Outcome of noting a ledger. combined stays false and atoms stays 0 on
 * every path. The four balances stay separate.
 */
struct SwarmNotNoBalanceResult {
    std::string code;
    bool combined{false};
    int64_t atoms{0};
};

/**
 * Note a ledger without combining balances. Order, first match wins:
 * an empty ledger_id is LEDGER. mixed_books is SEPARATE even when
 * want_combine is false. want_combine is HELD. Otherwise the note is
 * NOTED and err is cleared. combined stays false and atoms stays 0 on
 * every path. The four balances stay separate.
 */
SwarmNotNoBalanceResult SwarmNoteNotNoBalance(const SwarmNotNoBalance& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBALANCE_H
