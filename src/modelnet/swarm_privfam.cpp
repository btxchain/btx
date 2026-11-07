// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam.h>

#include <string>

namespace modelnet {

SwarmPrivFamResult SwarmNotePrivFam(const SwarmPrivFam& family, std::string& err)
{
    SwarmPrivFamResult result;
    result.published = false;
    // A private family is not published.
    if (family.family_id.empty()) {
        result.code = "FAMILY";
        result.published = false;
        err = "FAMILY";
        return result;
    }
    if (family.private_family) {
        result.code = "NOT_PUBLISHED";
        result.published = false;
        err = "NOT_PUBLISHED";
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
