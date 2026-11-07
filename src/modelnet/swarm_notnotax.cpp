// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotax.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoTaxResult SwarmNoteNotNoTax(const SwarmNotNoTax& note, std::string& err)
{
    SwarmNotNoTaxResult result;
    result.charged = false;
    result.atoms = 0;
    // Open-license local inference is not taxed.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.charged = false;
        result.atoms = 0;
        err = "LICENSE";
        return result;
    }
    if (note.open_license) {
        result.code = "NOT_CHARGED";
        result.charged = false;
        result.atoms = 0;
        err = "NOT_CHARGED";
        return result;
    }
    if (note.want_charge) {
        result.code = "NOT_CHARGED";
        result.charged = false;
        result.atoms = 0;
        err = "NOT_CHARGED";
        return result;
    }
    result.code = "NOTED";
    result.charged = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
