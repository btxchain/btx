// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/act.h>

#include <modelnet/swarm_sandboxgate/act_kind.h>
#include <modelnet/swarm_sandboxgate/book.h>
#include <modelnet/swarm_sandboxgate/capability.h>
#include <modelnet/swarm_sandboxgate/codes.h>
#include <modelnet/swarm_sandboxgate/journal.h>
#include <modelnet/swarm_sandboxgate/prefix.h>
#include <modelnet/swarm_sandboxgate/record.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmSandboxGateActApply(const SwarmSandboxGateBook& book,
                              SwarmSandboxGateJournal& journal,
                              const std::string& worker,
                              const std::string& path,
                              const std::string& capability,
                              int64_t now_ms,
                              std::string& err)
{
    const SwarmSandboxGateActKind kind = SwarmSandboxGateClassifyAct(book, worker, path, capability, now_ms);
    const char* code = SwarmSandboxGateActKindCode(kind);
    if (code != nullptr) {
        err = code;
        return false;
    }
    if (SwarmSandboxGatePrivatePath(path)) {
        err = kSwarmSandboxGatePrivateData;
        return false;
    }
    if (SwarmSandboxGateCapabilityBlank(capability)) {
        err = kSwarmSandboxGateCapability;
        return false;
    }
    const SwarmSandboxGateAction action = SwarmSandboxGateMakeAction(worker, path, capability, now_ms);
    if (!journal.record(action)) {
        err = kSwarmSandboxGateNotActed;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
