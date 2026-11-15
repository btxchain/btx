// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottax.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotTaxResult SwarmNoteNotTax(const SwarmNotTax& note, std::string& err)
{
    SwarmNotTaxResult result;
    result.taxed = false;
    result.atoms = 0;
    // Open-license local inference is not taxed.
    if (note.inference_id.empty()) {
        result.code = "INFERENCE";
        result.taxed = false;
        result.atoms = 0;
        err = "INFERENCE";
        return result;
    }
    if (note.open_license || note.want_tax) {
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
