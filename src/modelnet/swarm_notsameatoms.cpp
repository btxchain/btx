// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsameatoms.h>

#include <string>

namespace modelnet {

SwarmNotSameAtomsResult SwarmNoteNotSameAtoms(const SwarmNotSameAtoms& note, std::string& err)
{
    SwarmNotSameAtomsResult result;
    result.both = false;
    // The same atoms are never both escrow and collateral.
    if (note.atom_id.empty()) {
        result.code = "ATOMS";
        result.both = false;
        err = "ATOMS";
        return result;
    }
    if (note.escrow && note.collateral) {
        result.code = "REUSE";
        result.both = false;
        err = "REUSE";
        return result;
    }
    result.code = "NOTED";
    result.both = false;
    err.clear();
    return result;
}

} // namespace modelnet
