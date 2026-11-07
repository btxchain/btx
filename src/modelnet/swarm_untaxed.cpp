// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_untaxed.h>

namespace modelnet {

SwarmInferenceTaxResult SwarmNoteInferenceTax(const SwarmInferenceTax& tax, std::string& err)
{
    SwarmInferenceTaxResult result;
    result.taxed = false;
    if (tax.license_id.empty()) {
        result.code = "LICENSE";
        err = "LICENSE";
        return result;
    }
    if (tax.open_license && tax.local_inference) {
        result.code = "UNTAXED";
        err.clear();
        return result;
    }
    if (tax.want_tax) {
        result.code = "TAX_REFUSED";
        err = "TAX_REFUSED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
