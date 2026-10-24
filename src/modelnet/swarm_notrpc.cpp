// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrpc.h>

namespace modelnet {

SwarmNotRpcResult SwarmNoteNotRpc(const SwarmNotRpc& note, std::string& err)
{
    // This note does not register an RPC method.
    if (note.method.empty()) {
        err = "RPC";
        return SwarmNotRpcResult{"RPC", false};
    }
    if (note.want_add) {
        err = "NOT_ADDED";
        return SwarmNotRpcResult{"NOT_ADDED", false};
    }
    err.clear();
    return SwarmNotRpcResult{"NOTED", false};
}

} // namespace modelnet
