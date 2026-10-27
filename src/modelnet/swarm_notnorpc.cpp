// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorpc.h>

namespace modelnet {

SwarmNotNoRpcResult SwarmNoteNotNoRpc(const SwarmNotNoRpc& note, std::string& err)
{
    // This note adds no lab RPC name.
    if (note.method_id.empty()) {
        err = "METHOD";
        return SwarmNotNoRpcResult{"METHOD", false, false};
    }
    if (note.want_add) {
        err = "NOT_ADDED";
        return SwarmNotNoRpcResult{"NOT_ADDED", false, false};
    }
    err.clear();
    return SwarmNotNoRpcResult{"NOTED", false, false};
}

} // namespace modelnet
