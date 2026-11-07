// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoescrow2.h>

#include <string>

namespace modelnet {

SwarmNotNoEscrow2Result SwarmNoteNotNoEscrow2(const SwarmNotNoEscrow2& note, std::string& err)
{
    SwarmNotNoEscrow2Result result;
    result.booked = false;
    result.atoms = 0;
    if (note.atom_id.empty()) {
        result.code = "ATOMS";
        result.booked = false;
        result.atoms = 0;
        err = "ATOMS";
        return result;
    }
    // The same atoms are never both escrow and collateral.
    if (note.both_roles) {
        result.code = "HELD";
        result.booked = false;
        result.atoms = 0;
        err = "HELD";
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
