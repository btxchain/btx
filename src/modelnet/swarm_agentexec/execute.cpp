// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/execute.h>

#include <modelnet/swarm_agentexec/book.h>
#include <modelnet/swarm_agentexec/codes.h>
#include <modelnet/swarm_agentexec/journal.h>
#include <modelnet/swarm_agentexec/private.h>
#include <modelnet/swarm_agentexec/result.h>
#include <modelnet/swarm_agentexec/run.h>
#include <modelnet/swarm_agentexec/tool.h>

#include <string>

namespace modelnet {

bool SwarmAgentExecExecute(const SwarmAgentExecBook& book,
                           SwarmAgentExecJournal& journal,
                           SwarmAgentExecResult& result,
                           const std::string& tool,
                           const std::string& path,
                           const std::string& payload,
                           std::string& err)
{
    const SwarmAgentExecToolKind kind = SwarmAgentExecClassifyTool(tool);
    if (kind == SwarmAgentExecToolKind::Empty) {
        err = kSwarmAgentExecTool;
        return false;
    }
    if (kind == SwarmAgentExecToolKind::Net) {
        err = kSwarmAgentExecNetDenied;
        return false;
    }
    if (!book.Allows(path)) {
        err = kSwarmAgentExecDenied;
        return false;
    }
    if (SwarmAgentExecPrivatePath(path)) {
        err = kSwarmAgentExecPrivateData;
        return false;
    }
    if (payload.empty()) {
        err = kSwarmAgentExecPayload;
        return false;
    }
    if (kind != SwarmAgentExecToolKind::Sha256) {
        err = kSwarmAgentExecTool;
        return false;
    }
    return SwarmAgentExecRun(journal, result, path, payload, err);
}

} // namespace modelnet
