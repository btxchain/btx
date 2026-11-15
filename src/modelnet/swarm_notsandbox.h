// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSANDBOX_H
#define BTX_MODELNET_SWARM_NOTSANDBOX_H

#include <string>

namespace modelnet {

/**
 * A local note about one executor. want_launch asks this note to start
 * a child, torchrun, NCCL, FSDP, or a sandbox.
 *
 * This note does not start a child, torchrun, NCCL, FSDP, or a sandbox.
 * launched and restricted stay false on every path.
 */
struct SwarmNotSandbox {
    std::string executor_id;
    bool want_launch{false};
};

/**
 * Outcome of noting a sandbox request. launched and restricted stay false
 * on every path: this note does not start a child, torchrun, NCCL, FSDP,
 * or a sandbox.
 */
struct SwarmNotSandboxResult {
    std::string code;
    bool launched{false};
    bool restricted{false};
};

/**
 * Note a sandbox request without starting a child, torchrun, NCCL, FSDP,
 * or a sandbox.
 * Order, first match wins: an empty executor_id is EXECUTOR.
 * want_launch is SANDBOX_ABSENT.
 * Otherwise the note is NOTED and err is clear.
 * launched and restricted stay false on every path.
 */
SwarmNotSandboxResult SwarmNoteNotSandbox(const SwarmNotSandbox& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSANDBOX_H
