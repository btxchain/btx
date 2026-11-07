// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTRPC_H
#define BITCOIN_MODELNET_SWARM_NOTRPC_H

#include <string>

namespace modelnet {

struct SwarmNotRpc {
    std::string method;
    bool want_add{false};
};

struct SwarmNotRpcResult {
    std::string code;
    bool added{false};
};

/** Record a note only. This note does not register an RPC method. */
SwarmNotRpcResult SwarmNoteNotRpc(const SwarmNotRpc& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTRPC_H
