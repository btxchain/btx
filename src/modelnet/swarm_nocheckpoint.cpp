// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nocheckpoint.h>

namespace modelnet {

SwarmNoCheckpointResult SwarmNoteNoCheckpoint(const SwarmNoCheckpoint& note, std::string& err)
{
    SwarmNoCheckpointResult result;
    result.published = false;
    if (note.run_id.empty()) {
        result.code = "CHECK";
        result.published = false;
        err = "CHECK";
        return result;
    }
    // A step that did not save a checkpoint does not publish one.
    if (!note.checkpoint_saved) {
        result.code = "NO_CHECKPOINT";
        result.published = false;
        err = "NO_CHECKPOINT";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
