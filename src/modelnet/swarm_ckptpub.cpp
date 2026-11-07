// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptpub.h>

namespace modelnet {

SwarmCheckpointNoteResult SwarmNoteCheckpoint(const SwarmCheckpointNote& note, std::string& err)
{
    SwarmCheckpointNoteResult result;
    result.published = false;
    if (note.checkpoint_id.empty() || note.digest.empty()) {
        result.code = "CHECKPOINT";
        err = "CHECKPOINT";
        return result;
    }
    if (!note.body_complete) {
        result.code = "TRUNCATED";
        err = "TRUNCATED";
        return result;
    }
    if (note.interrupted) {
        result.code = "INTERRUPTED";
        err = "INTERRUPTED";
        return result;
    }
    result.published = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
