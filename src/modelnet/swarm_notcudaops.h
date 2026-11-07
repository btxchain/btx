// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCUDAOPS_H
#define BTX_MODELNET_SWARM_NOTCUDAOPS_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. ops_present records whether compiled CUDA
 * ops are present. want_transfer asks this note to move bytes.
 *
 * Missing compiled CUDA ops move no bytes. transferred and bytes_moved stay
 * false on every path.
 */
struct SwarmNotCudaOps {
    std::string engine_id;
    bool ops_present{false};
    bool want_transfer{false};
};

/**
 * Outcome of noting a CUDA ops request. transferred and bytes_moved stay
 * false on every path: missing compiled CUDA ops move no bytes.
 */
struct SwarmNotCudaOpsResult {
    std::string code;
    bool transferred{false};
    bool bytes_moved{false};
};

/**
 * Note a CUDA ops request without moving bytes.
 * Order, first match wins: an empty engine_id is ENGINE.
 * Absent compiled CUDA ops is ENGINE_ABSENT, even when want_transfer is false.
 * want_transfer is ENGINE_ABSENT.
 * Otherwise the note is NOTED and err is clear.
 * transferred and bytes_moved stay false on every path. Missing compiled
 * CUDA ops move no bytes.
 */
SwarmNotCudaOpsResult SwarmNoteNotCudaOps(const SwarmNotCudaOps& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCUDAOPS_H
