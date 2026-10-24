// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoopenlic.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoOpenLicResult SwarmNoteNotNoOpenLic(const SwarmNotNoOpenLic& note, std::string& err)
{
    SwarmNotNoOpenLicResult result;
    result.taxed = false;
    result.atoms = 0;
    // Open-license local inference is not taxed. This note moves no atoms.
    if (note.infer_id.empty()) {
        result.code = "INFER";
        result.taxed = false;
        result.atoms = 0;
        err = "INFER";
        return result;
    }
    if (note.open_license) {
        result.code = "NOT_TAXED";
        result.taxed = false;
        result.atoms = 0;
        err = "NOT_TAXED";
        return result;
    }
    if (note.want_tax) {
        result.code = "NOT_TAXED";
        result.taxed = false;
        result.atoms = 0;
        err = "NOT_TAXED";
        return result;
    }
    result.code = "NOTED";
    result.taxed = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
