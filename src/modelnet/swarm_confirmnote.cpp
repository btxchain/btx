// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_confirmnote.h>

namespace modelnet {

SwarmConfirmNoteResult SwarmNoteConfirmLocal(const SwarmConfirmNote& note, std::string& err)
{
    // A confirmation count is not a broadcast.
    if (note.channel_id.empty()) {
        err = "CHANNEL";
        return SwarmConfirmNoteResult{"CHANNEL", false, 0};
    }
    if (note.confirmations < 0) {
        err = "RANGE";
        return SwarmConfirmNoteResult{"RANGE", false, 0};
    }
    if (note.want_broadcast) {
        err = "HELD";
        return SwarmConfirmNoteResult{"HELD", false, note.confirmations};
    }
    err.clear();
    return SwarmConfirmNoteResult{"NOTED", false, note.confirmations};
}

} // namespace modelnet
