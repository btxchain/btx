// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocollateral2.h>

#include <string>

namespace modelnet {

SwarmNotNoCollateral2Result SwarmNoteNotNoCollateral2(const SwarmNotNoCollateral2& note, std::string& err)
{
    SwarmNotNoCollateral2Result result;
    result.booked = false;
    result.atoms = 0;
    if (note.collateral_id.empty()) {
        result.code = "COLLATERAL";
        result.booked = false;
        result.atoms = 0;
        err = "COLLATERAL";
        return result;
    }
    // Reused collateral is not booked again.
    if (note.reused) {
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
