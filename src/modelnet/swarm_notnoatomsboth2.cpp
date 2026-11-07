// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoatomsboth2.h>

#include <string>

namespace modelnet {

SwarmNotNoAtomsBoth2Result SwarmNoteNotNoAtomsBoth2(const SwarmNotNoAtomsBoth2& note, std::string& err)
{
    SwarmNotNoAtomsBoth2Result result;
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
