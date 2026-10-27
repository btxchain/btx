// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/inspect.h>

#include <modelnet/swarm_sandboxgate/book.h>
#include <modelnet/swarm_sandboxgate/journal.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmSandboxGateGranted(const SwarmSandboxGateBook& book, const std::string& worker)
{
    return book.worker_granted(worker);
}

std::size_t SwarmSandboxGateActionCount(const SwarmSandboxGateJournal& journal)
{
    return journal.size();
}

bool SwarmSandboxGateNetworkPermitted(const SwarmSandboxGateBook& book,
                                      const std::string& worker,
                                      int64_t now_ms)
{
    return book.network_live(worker, now_ms);
}

} // namespace modelnet
