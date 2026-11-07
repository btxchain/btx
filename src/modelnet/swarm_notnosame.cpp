// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosame.h>

#include <string>

namespace modelnet {

SwarmNotNoSameResult SwarmNoteNotNoSame(const SwarmNotNoSame& note, std::string& err)
{
    SwarmNotNoSameResult result;
    result.counted_twice = false;
    result.atoms = 0;
    // The same atoms are never both escrow and collateral.
    if (note.atom_id.empty()) {
        result.code = "ATOM";
        result.counted_twice = false;
        result.atoms = 0;
        err = "ATOM";
        return result;
    }
    if (note.escrow && note.collateral) {
        result.code = "SAME_ATOMS";
        result.counted_twice = false;
        result.atoms = 0;
        err = "SAME_ATOMS";
        return result;
    }
    result.code = "NOTED";
    result.counted_twice = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
