// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFOURBAL_H
#define BTX_MODELNET_SWARM_NOTNOFOURBAL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about four balances. book_id names the book.
 * mixed marks balances that must stay apart. want_merge asks this note
 * to merge them.
 *
 * The four balances stay separate. merged stays false and atoms stays
 * 0 on every path.
 */
struct SwarmNotNoFourBal {
    std::string book_id;
    bool mixed{false};
    bool want_merge{false};
};

/**
 * Outcome of noting four balances. merged stays false and atoms stays
 * 0 on every path. The four balances stay separate.
 */
struct SwarmNotNoFourBalResult {
    std::string code;
    bool merged{false};
    int64_t atoms{0};
};

/**
 * Note four balances without merging them. Order, first match wins:
 * an empty book_id is BOOK. mixed is SEPARATE even when want_merge is
 * false. want_merge is HELD. Otherwise the note is NOTED and err is
 * cleared. merged stays false and atoms stays 0 on every path. The
 * four balances stay separate.
 */
SwarmNotNoFourBalResult SwarmNoteNotNoFourBal(const SwarmNotNoFourBal& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFOURBAL_H
