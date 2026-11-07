// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoleakgrad2.h>

#include <string>

namespace modelnet {

SwarmNotNoLeakGrad2Result SwarmNoteNotNoLeakGrad2(const SwarmNotNoLeakGrad2& note, std::string& err)
{
    // A gradient update is not exported.
    SwarmNotNoLeakGrad2Result result;
    result.exported = false;
    if (note.update_id.empty()) {
        result.code = "UPDATE";
        result.exported = false;
        err = "UPDATE";
        return result;
    }
    if (note.gradient) {
        result.code = "NOT_EXPORTED";
        result.exported = false;
        err = "NOT_EXPORTED";
        return result;
    }
    if (note.want_export) {
        result.code = "HELD";
        result.exported = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.exported = false;
    err.clear();
    return result;
}

} // namespace modelnet
