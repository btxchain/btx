// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_PLANE_H
#define BTX_MODELNET_SWARM_AGENTS_PLANE_H

#include <modelnet/swarm_agents/account.h>
#include <modelnet/swarm_agents/dag.h>
#include <modelnet/swarm_agents/gate.h>
#include <modelnet/swarm_agents/lease.h>
#include <modelnet/swarm_agents/registry.h>
#include <modelnet/swarm_agents/shared.h>
#include <modelnet/swarm_agents/trace.h>
#include <modelnet/swarm_agents/types.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process agent execution plane.
 *
 * Tasks are scheduled on a DAG, admitted through a sandbox gate, and
 * run as builtins in the caller. launched() stays false because no
 * child process is started. A refused run stores no result.
 * Commit and Cancel append a trace row only when they succeed.
 * The lease epoch starts at 1. A commit whose epoch is not the
 * current epoch is STALE_EPOCH and does not commit. Shared results
 * keep the first hash.
 */
class SwarmAgentPlane {
public:
    bool Add(const std::string& task, const std::vector<std::string>& deps, std::string& err);
    std::vector<std::string> Ready() const;
    bool Commit(const std::string& task, const std::string& hash, std::string& err);
    bool Cancel(const std::string& task, std::string& err);
    std::string CommittedHash(const std::string& task) const;

    bool Run(const SwarmAgentRunRequest& request, std::string& err);
    bool ran(const std::string& task) const;
    bool launched() const;
    bool has_result(const std::string& task) const;
    uint64_t step(const std::string& task) const;
    std::string result_hash(const std::string& task) const;

    bool Grant(const std::string& lease, int64_t until, int64_t now, std::string& err);
    bool admitted() const;
    uint64_t epoch() const;
    const std::string& lease_id() const;
    int64_t lease_until() const;
    bool CommitEpoch(uint64_t epoch, const std::string& task, const std::string& hash, std::string& err);

    bool Charge(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err);
    bool Release(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err);
    int64_t Threads(const std::string& agent) const;
    int64_t Memory(const std::string& agent) const;

    bool Append(const std::string& task, const std::string& event, std::string& err);
    std::vector<SwarmAgentTraceRow> Trace() const;

    bool Publish(const std::string& key, const std::string& hash, std::string& err);
    bool Attach(const std::string& consumer, const std::string& key, const std::string& hash, std::string& err);
    std::string Shared(const std::string& key) const;
    bool attached(const std::string& consumer, const std::string& key) const;

private:
    SwarmAgentDag m_dag;
    SwarmAgentGate m_gate;
    SwarmAgentRegistry m_registry;
    SwarmAgentLeaseBook m_lease;
    SwarmAgentAccount m_account;
    SwarmAgentTraceLog m_trace;
    SwarmAgentSharedResult m_shared;
    std::map<std::string, SwarmAgentBuiltinResult> m_results;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_PLANE_H
