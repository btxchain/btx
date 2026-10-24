// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/run.h>

#include <modelnet/swarm_agentexec/codes.h>
#include <modelnet/swarm_agentexec/digest.h>
#include <modelnet/swarm_agentexec/journal.h>
#include <modelnet/swarm_agentexec/result.h>

#include <string>

namespace modelnet {

bool SwarmAgentExecRun(SwarmAgentExecJournal& journal,
                       SwarmAgentExecResult& result,
                       const std::string& path,
                       const std::string& payload,
                       std::string& err)
{
    if (payload.empty()) {
        err = kSwarmAgentExecPayload;
        return false;
    }
    if (journal.Seen(path, payload)) {
        err = kSwarmAgentExecReplay;
        return false;
    }
    const std::string digest = SwarmAgentExecDigest(payload);
    if (!journal.Put(path, payload, digest)) {
        err = kSwarmAgentExecReplay;
        return false;
    }
    result.Store(digest);
    err.clear();
    return true;
}

} // namespace modelnet
