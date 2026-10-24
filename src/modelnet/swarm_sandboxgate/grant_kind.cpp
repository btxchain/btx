// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/grant_kind.h>

#include <modelnet/swarm_sandboxgate/blank.h>
#include <modelnet/swarm_sandboxgate/book.h>
#include <modelnet/swarm_sandboxgate/capability.h>
#include <modelnet/swarm_sandboxgate/clock.h>
#include <modelnet/swarm_sandboxgate/codes.h>
#include <modelnet/swarm_sandboxgate/replay.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

SwarmSandboxGateGrantKind SwarmSandboxGateClassifyGrant(const SwarmSandboxGateBook& book,
                                                        const std::string& worker,
                                                        const std::string& path_prefix,
                                                        const std::vector<std::string>& capabilities,
                                                        int64_t until_ms)
{
    if (SwarmSandboxGateBlank(worker)) return SwarmSandboxGateGrantKind::Worker;
    if (SwarmSandboxGateBlank(path_prefix)) return SwarmSandboxGateGrantKind::Path;
    if (SwarmSandboxGateUntilRejected(until_ms)) return SwarmSandboxGateGrantKind::Timeout;
    if (SwarmSandboxGateCapabilitiesEmpty(capabilities)) return SwarmSandboxGateGrantKind::Capability;
    if (SwarmSandboxGateIsReplay(book, worker, path_prefix)) return SwarmSandboxGateGrantKind::Replay;
    return SwarmSandboxGateGrantKind::Store;
}

const char* SwarmSandboxGateGrantKindCode(SwarmSandboxGateGrantKind kind)
{
    switch (kind) {
    case SwarmSandboxGateGrantKind::Store:
        return nullptr;
    case SwarmSandboxGateGrantKind::Worker:
        return kSwarmSandboxGateWorker;
    case SwarmSandboxGateGrantKind::Path:
        return kSwarmSandboxGatePath;
    case SwarmSandboxGateGrantKind::Timeout:
        return kSwarmSandboxGateTimeout;
    case SwarmSandboxGateGrantKind::Capability:
        return kSwarmSandboxGateCapability;
    case SwarmSandboxGateGrantKind::Replay:
        return kSwarmSandboxGateReplay;
    }
    return kSwarmSandboxGateWorker;
}

} // namespace modelnet
