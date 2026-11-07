// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SANDBOX_H
#define BTX_MODELNET_SWARM_SANDBOX_H

#include <util/fs.h>

#include <string>

namespace modelnet {

/**
 * Sandbox helper presence. An empty path is SANDBOX. A missing path or a
 * path that is not a regular file is SANDBOX_ABSENT. A regular file is
 * INSTALLED. launched is always false: this function does not exec the
 * helper. An installed helper is not a running sandbox and is not
 * resource-limit enforcement.
 */
struct SwarmSandboxStatus {
    bool present{false};
    bool launched{false};
    std::string code;
};

SwarmSandboxStatus SwarmProbeSandbox(const fs::path& helper, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SANDBOX_H
