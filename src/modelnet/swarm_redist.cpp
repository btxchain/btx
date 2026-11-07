// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_redist.h>

namespace modelnet {

SwarmRedistributeResult SwarmNoteRedistribute(const SwarmRedistribute& note, std::string& err)
{
    SwarmRedistributeResult result;
    result.redistribution_allowed = false;
    if (note.license_id.empty()) {
        result.code = "GRANT";
        err = "GRANT";
        return result;
    }
    if (note.want_redistribute && !note.operator_grant) {
        result.code = "NOT_REDISTRIBUTION";
        err = "NOT_REDISTRIBUTION";
        return result;
    }
    if (note.want_redistribute) {
        result.redistribution_allowed = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    result.redistribution_allowed = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
