// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNORPC_H
#define BTX_MODELNET_SWARM_NOTNORPC_H

#include <string>

namespace modelnet {

struct SwarmNotNoRpc {
    std::string method_id;
    bool want_add{false};
};

struct SwarmNotNoRpcResult {
    std::string code;
    bool added{false};
    bool called{false};
};

/** Record a note only. This note adds no lab RPC name. */
SwarmNotNoRpcResult SwarmNoteNotNoRpc(const SwarmNotNoRpc& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNORPC_H
