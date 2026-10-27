// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyonly.h>

namespace modelnet {

SwarmFamilyOnlyResult SwarmNoteFamilyOnly(const SwarmFamilyOnly& note, std::string& err)
{
    SwarmFamilyOnlyResult result;
    result.shared = false;
    result.bytes_moved = false;
    if (note.page_id.empty()) {
        result.code = "FAMILY";
        result.shared = false;
        result.bytes_moved = false;
        err = "FAMILY";
        return result;
    }
    // Family membership is not KV compatibility.
    if (note.same_family && !note.compatible) {
        result.code = "FAMILY_NOT_COMPAT";
        result.shared = false;
        result.bytes_moved = false;
        err = "FAMILY_NOT_COMPAT";
        return result;
    }
    if (!note.same_family) {
        result.code = "SEPARATE";
        result.shared = false;
        result.bytes_moved = false;
        err = "SEPARATE";
        return result;
    }
    if (note.want_share) {
        result.code = "HELD";
        result.shared = false;
        result.bytes_moved = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
