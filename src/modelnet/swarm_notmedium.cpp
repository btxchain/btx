// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmedium.h>

#include <string>

namespace modelnet {

SwarmNotMediumResult SwarmNoteNotMedium(const SwarmNotMedium& note, std::string& err)
{
    SwarmNotMediumResult result;
    result.executed = false;
    result.trained = false;
    // This note does not run a medium adapter or train.
    if (note.adapter_id.empty()) {
        result.code = "ADAPTER";
        result.executed = false;
        result.trained = false;
        err = "ADAPTER";
        return result;
    }
    if (note.want_execute) {
        result.code = "NOT_EXECUTED";
        result.executed = false;
        result.trained = false;
        err = "NOT_EXECUTED";
        return result;
    }
    result.code = "NOTED";
    result.executed = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
