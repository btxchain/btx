// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familydir.h>

#include <string>

namespace modelnet {

SwarmFamilyDirResult SwarmNoteFamilyDir(const SwarmFamilyDir& family, std::string& err)
{
    SwarmFamilyDirResult result;
    result.published = false;
    // A family directory publish request is held and publishes nothing.
    if (family.family_id.empty()) {
        result.code = "FAMILY";
        result.published = false;
        err = "FAMILY";
        return result;
    }
    if (family.want_publish) {
        result.code = "HELD";
        result.published = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
