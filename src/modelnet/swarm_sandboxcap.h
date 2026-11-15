// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SANDBOXCAP_H
#define BTX_MODELNET_SWARM_SANDBOXCAP_H

#include <string>

namespace modelnet {

// A sandbox raise stays capped. A raise request is noted, not applied.
struct SwarmSandboxCap {
    std::string node_id;
    bool want_raise;
};

struct SwarmSandboxCapResult {
    std::string code;
    bool raised;
};

SwarmSandboxCapResult SwarmNoteSandboxCap(const SwarmSandboxCap& node, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SANDBOXCAP_H
