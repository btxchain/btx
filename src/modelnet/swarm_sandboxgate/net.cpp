// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/net.h>

#include <modelnet/swarm_sandboxgate/book.h>
#include <modelnet/swarm_sandboxgate/net_kind.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmSandboxGateNetPermit(const SwarmSandboxGateBook& book,
                               const std::string& worker,
                               const std::string& host_id,
                               int64_t now_ms,
                               std::string& err)
{
    const SwarmSandboxGateNetKind kind = SwarmSandboxGateClassifyNet(book, worker, host_id, now_ms);
    const char* code = SwarmSandboxGateNetKindCode(kind);
    if (code != nullptr) {
        err = code;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
