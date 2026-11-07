// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoopenlic2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoOpenLic2Result SwarmNoteNotNoOpenLic2(const SwarmNotNoOpenLic2& note, std::string& err)
{
    SwarmNotNoOpenLic2Result result;
    result.taxed = false;
    result.atoms = 0;
    // Open-license local inference is not taxed. This note moves no atoms.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.taxed = false;
        result.atoms = 0;
        err = "LICENSE";
        return result;
    }
    // open_local is NOT_TAXED even when want_tax is false.
    if (note.open_local) {
        result.code = "NOT_TAXED";
        result.taxed = false;
        result.atoms = 0;
        err = "NOT_TAXED";
        return result;
    }
    // This note moves no atoms. Open-license local inference is not taxed.
    if (note.want_tax) {
        result.code = "HELD";
        result.taxed = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.taxed = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
