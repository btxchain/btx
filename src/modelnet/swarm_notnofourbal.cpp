// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofourbal.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoFourBalResult SwarmNoteNotNoFourBal(const SwarmNotNoFourBal& note, std::string& err)
{
    SwarmNotNoFourBalResult result;
    result.merged = false;
    result.atoms = 0;
    // The four balances stay separate.
    if (note.book_id.empty()) {
        result.code = "BOOK";
        result.merged = false;
        result.atoms = 0;
        err = "BOOK";
        return result;
    }
    if (note.mixed) {
        result.code = "SEPARATE";
        result.merged = false;
        result.atoms = 0;
        err = "SEPARATE";
        return result;
    }
    if (note.want_merge) {
        result.code = "HELD";
        result.merged = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.merged = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
