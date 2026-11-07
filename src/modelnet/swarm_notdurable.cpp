// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdurable.h>

#include <string>

namespace modelnet {

SwarmNotDurableResult SwarmNoteNotDurable(const SwarmNotDurable& note, std::string& err)
{
    SwarmNotDurableResult result;
    result.persisted = false;
    result.bytes_moved = false;
    // This note does not write a store.
    if (note.state_id.empty()) {
        result.code = "STATE";
        result.persisted = false;
        result.bytes_moved = false;
        err = "STATE";
        return result;
    }
    if (note.want_persist) {
        result.code = "NOT_PERSISTED";
        result.persisted = false;
        result.bytes_moved = false;
        err = "NOT_PERSISTED";
        return result;
    }
    result.code = "NOTED";
    result.persisted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
