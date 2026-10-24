// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/replay.h>

#include <modelnet/swarm_sandboxgate/blank.h>
#include <modelnet/swarm_sandboxgate/book.h>

#include <string>

namespace modelnet {

bool SwarmSandboxGateIsReplay(const SwarmSandboxGateBook& book,
                              const std::string& worker,
                              const std::string& path_prefix)
{
    if (SwarmSandboxGateBlank(worker) || SwarmSandboxGateBlank(path_prefix)) return false;
    return book.prefix_held(worker, path_prefix);
}

} // namespace modelnet
