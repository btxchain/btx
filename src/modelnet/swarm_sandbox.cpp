// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandbox.h>

namespace modelnet {

SwarmSandboxStatus SwarmProbeSandbox(const fs::path& helper, std::string& err)
{
    SwarmSandboxStatus status;
    if (helper.empty()) {
        status.code = "SANDBOX";
        err = "SANDBOX";
        return status;
    }
    if (!fs::exists(helper) || !fs::is_regular_file(helper)) {
        status.code = "SANDBOX_ABSENT";
        err = "SANDBOX_ABSENT";
        return status;
    }
    status.present = true;
    status.code = "INSTALLED";
    err.clear();
    return status;
}

} // namespace modelnet
