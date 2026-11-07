// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/grant.h>

#include <modelnet/swarm_sandboxgate/book.h>
#include <modelnet/swarm_sandboxgate/codes.h>
#include <modelnet/swarm_sandboxgate/grant_kind.h>
#include <modelnet/swarm_sandboxgate/record.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmSandboxGateGrantApply(SwarmSandboxGateBook& book,
                                const std::string& worker,
                                const std::string& path_prefix,
                                const std::vector<std::string>& capabilities,
                                bool network,
                                int64_t until_ms,
                                std::string& err)
{
    const SwarmSandboxGateGrantKind kind =
        SwarmSandboxGateClassifyGrant(book, worker, path_prefix, capabilities, until_ms);
    const char* code = SwarmSandboxGateGrantKindCode(kind);
    if (code != nullptr) {
        err = code;
        return false;
    }
    const SwarmSandboxGateGrant grant =
        SwarmSandboxGateMakeGrant(worker, path_prefix, capabilities, network, until_ms);
    if (!book.store(grant)) {
        err = book.prefix_held(worker, path_prefix) ? std::string{kSwarmSandboxGateReplay}
                                                    : std::string{kSwarmSandboxGatePath};
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
