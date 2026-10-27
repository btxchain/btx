// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/blank.h>

#include <string>

namespace modelnet {

bool SwarmSandboxGateBlank(const std::string& text)
{
    return text.empty();
}

} // namespace modelnet
