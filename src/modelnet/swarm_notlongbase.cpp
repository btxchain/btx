// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notlongbase.h>

#include <string>

namespace modelnet {

SwarmNotLongBaseResult SwarmNoteNotLongBase(const SwarmNotLongBase& note, std::string& err)
{
    SwarmNotLongBaseResult result;
    result.executed = false;
    result.trained = false;
    // This note does not run a long base checkpoint or train.
    if (note.checkpoint_id.empty()) {
        result.code = "CHECKPOINT";
        result.executed = false;
        result.trained = false;
        err = "CHECKPOINT";
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
