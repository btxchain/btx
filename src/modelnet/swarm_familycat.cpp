// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familycat.h>

#include <string>

namespace modelnet {

SwarmFamilyCatResult SwarmCatalogFamily(const SwarmFamilyCat& family, std::string& err)
{
    // A local catalog can list a public family and does not publish a private one.
    SwarmFamilyCatResult result;
    result.published = false;
    if (family.family_id.empty()) {
        result.code = "FAMILY";
        result.published = false;
        result.listed = false;
        err = "FAMILY";
        return result;
    }
    if (family.private_family) {
        result.code = "NOT_PUBLISHED";
        result.published = false;
        result.listed = false;
        err = "NOT_PUBLISHED";
        return result;
    }
    if (family.want_publish) {
        result.code = "HELD";
        result.published = false;
        result.listed = true;
        err = "HELD";
        return result;
    }
    if (family.want_list) {
        result.code = "NOTED";
        result.published = false;
        result.listed = true;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.listed = false;
    err.clear();
    return result;
}

} // namespace modelnet
