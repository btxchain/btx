// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoescrowboth2.h>

#include <string>

namespace modelnet {

SwarmNotNoEscrowBoth2Result SwarmNoteNotNoEscrowBoth2(const SwarmNotNoEscrowBoth2& note, std::string& err)
{
    SwarmNotNoEscrowBoth2Result result;
    result.booked = false;
    result.atoms = 0;
    if (note.ledger_id.empty()) {
        result.code = "LEDGER";
        result.booked = false;
        result.atoms = 0;
        err = "LEDGER";
        return result;
    }
    // The same atoms are never both escrow and collateral.
    if (note.same_atoms) {
        result.code = "NOT_BOTH";
        result.booked = false;
        result.atoms = 0;
        err = "NOT_BOTH";
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
