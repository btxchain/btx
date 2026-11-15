// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOESCROW_H
#define BTX_MODELNET_SWARM_NOTNOESCROW_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one book. same_atoms marks the atoms as already
 * used as both escrow and collateral. want_book asks this note to book it.
 *
 * The same atoms are never both escrow and collateral.
 * booked stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoEscrow {
    std::string book_id;
    bool same_atoms{false};
    bool want_book{false};
};

/**
 * Outcome of noting a book. booked stays false and atoms stays 0 on
 * every path: the same atoms are never both escrow and collateral.
 */
struct SwarmNotNoEscrowResult {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

/**
 * Note a book without treating the same atoms as both escrow and collateral.
 * Order, first match wins: an empty book_id is BOOK.
 * If same_atoms is true, the note is SAME_ATOMS even when want_book is false.
 * want_book is HELD. Otherwise the note is NOTED and err is cleared.
 * booked stays false and atoms stays 0 on every path. The same atoms are
 * never both escrow and collateral.
 */
SwarmNotNoEscrowResult SwarmNoteNotNoEscrow(const SwarmNotNoEscrow& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOESCROW_H
