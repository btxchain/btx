// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsubscribe.h>

namespace modelnet {

SwarmNotSubscribeResult SwarmNoteNotSubscribe(const SwarmNotSubscribe& note, std::string& err)
{
    // This note does not subscribe and does not adopt.
    if (note.model_id.empty()) {
        err = "MODEL";
        return SwarmNotSubscribeResult{"MODEL", false, false};
    }
    if (note.want_subscribe) {
        err = "NOT_SUBSCRIBED";
        return SwarmNotSubscribeResult{"NOT_SUBSCRIBED", false, false};
    }
    err.clear();
    return SwarmNotSubscribeResult{"NOTED", false, false};
}

} // namespace modelnet
