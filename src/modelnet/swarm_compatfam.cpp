// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_compatfam.h>

#include <string>

namespace modelnet {

SwarmCompatFamResult SwarmNoteCompatFam(const SwarmCompatFam& page, std::string& err)
{
    SwarmCompatFamResult result;
    result.shared = false;
    // Family membership is not compatibility.
    if (page.page_id.empty()) {
        result.code = "PAGE";
        result.shared = false;
        err = "PAGE";
        return result;
    }
    if (page.same_family) {
        result.code = "NOT_COMPAT";
        result.shared = false;
        err = "NOT_COMPAT";
        return result;
    }
    if (page.want_share) {
        result.code = "HELD";
        result.shared = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    err.clear();
    return result;
}

} // namespace modelnet
