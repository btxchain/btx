// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_openlic.h>

namespace modelnet {

// Open-license local inference is not taxed.
SwarmOpenLicResult SwarmNoteOpenLicense(const SwarmOpenLic& license, std::string& err)
{
    SwarmOpenLicResult out;
    out.taxed = false;
    out.atoms = 0;
    if (license.license_id.empty()) {
        out.code = "LICENSE";
        err = "LICENSE";
        return out;
    }
    if (license.open_local) {
        out.code = "NOT_TAXED";
        err = "NOT_TAXED";
        return out;
    }
    if (license.want_tax) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
