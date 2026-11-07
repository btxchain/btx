// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoescrow.h>

#include <string>

namespace modelnet {

SwarmNotNoEscrowResult SwarmNoteNotNoEscrow(const SwarmNotNoEscrow& note, std::string& err)
{
    SwarmNotNoEscrowResult result;
    result.booked = false;
    result.atoms = 0;
    if (note.book_id.empty()) {
        result.code = "BOOK";
        result.booked = false;
        result.atoms = 0;
        err = "BOOK";
        return result;
    }
    // The same atoms are never both escrow and collateral.
    if (note.same_atoms) {
        result.code = "SAME_ATOMS";
        result.booked = false;
        result.atoms = 0;
        err = "SAME_ATOMS";
        return result;
    }
    if (note.want_book) {
        result.code = "HELD";
        result.booked = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.booked = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
