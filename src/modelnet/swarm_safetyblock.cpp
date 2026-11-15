// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_safetyblock.h>

namespace modelnet {

SwarmSafetyBlockResult SwarmNoteSafetyBlock(const SwarmSafetyBlock& note, std::string& err)
{
    SwarmSafetyBlockResult result;
    result.graduated = false;
    if (note.candidate_id.empty()) {
        result.code = "SAFETY";
        err = "SAFETY";
        return result;
    }
    if (note.safety_fail || note.broad_regression) {
        result.code = "BLOCK";
        err = "BLOCK";
        return result;
    }
    if (note.want_graduate) {
        result.graduated = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    result.graduated = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
