// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTCLASS_H
#define BITCOIN_MODELNET_SWARM_AGENTCLASS_H

#include <modelnet/swarm_agentexec/swarm_agentexec.h>
#include <modelnet/swarm_agentrun/swarm_agentrun.h>
#include <modelnet/swarm_sandboxgate/swarm_sandboxgate.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Empty task, worker, or prefix on Admit. Nothing is stored. Unknown work task. Nothing is hashed. */
inline constexpr char SWARM_AGENTCLASS_TASK[] = "TASK";

/** The same task was admitted again. The first task, prefix, and grant stay. */
inline constexpr char SWARM_AGENTCLASS_REPLAY[] = "REPLAY";

/** until_ms is below 0. Nothing is stored. */
inline constexpr char SWARM_AGENTCLASS_TIMEOUT[] = "TIMEOUT";

/** Spawn refuses because no sandbox is present. Nothing is launched. */
inline constexpr char SWARM_AGENTCLASS_SANDBOX_ABSENT[] = "SANDBOX_ABSENT";

/** Capability and in-process tool name passed to the sandbox gate and the executor. */
inline constexpr char SWARM_AGENTCLASS_SHA256[] = "sha256";

/**
 * Path Private asks the sandbox gate to judge.
 * A grant of a prefix of this path does not make the action allowable.
 */
inline constexpr char SWARM_AGENTCLASS_PRIVATE_PATH[] = "private/secret";

/**
 * In-process agent session.
 * This class owns one SwarmAgentRun, one SwarmAgentExec, and one
 * SwarmSandboxGate. It calls those engines. It does not rebuild the task
 * forest and it does not hash a payload itself.
 *
 * Admit stores a root task, an executor prefix, and one sandbox grant.
 * An empty task, worker, or prefix is TASK and stores nothing.
 * until_ms below 0 is TIMEOUT and stores nothing.
 * The task is added with an empty parent. The prefix is allowed on the
 * executor. The worker is granted that prefix, capability sha256, network
 * false, and until_ms. A second admit of the same task is REPLAY.
 *
 * Work asks the sandbox gate to Act for that worker, path, capability
 * sha256, and now_ms. If Act fails, Work returns false with the gate error
 * and does not hash. If Act passes, Work calls SwarmAgentExec::Execute for
 * tool sha256. Work returns true only when Execute returns true.
 * digest() is the executor result. ran() follows the executor.
 *
 * Net calls the sandbox gate. Network is not granted, so the gate returns
 * NET_DENIED while the grant is live. connected() stays false.
 *
 * Spawn calls SwarmAgentRun::Run and SwarmSandboxGate::Run. Both refuse
 * with SANDBOX_ABSENT. launched() stays false. No child process is started.
 *
 * Private asks the gate to Act on private/secret. That path is PRIVATE_DATA
 * even when a prefix of it was granted. Nothing is hashed.
 *
 * launched() and connected() stay false. This session does not spawn,
 * exec, open a socket, or spend.
 */
class SwarmAgentClass {
public:
    bool Admit(const std::string& task, const std::string& worker, const std::string& prefix, int64_t until_ms, std::string& err);
    bool Work(const std::string& task, const std::string& worker, const std::string& path, const std::string& payload, int64_t now_ms,
              std::string& err);
    bool Net(const std::string& worker, const std::string& host, int64_t now_ms, std::string& err);
    bool Spawn(std::string& err);
    bool Private(const std::string& worker, const std::string& payload, int64_t now_ms, std::string& err);

    std::string digest() const;
    bool ran() const;
    bool launched() const;
    bool connected() const;

private:
    SwarmAgentRun m_run;
    SwarmAgentExec m_exec;
    SwarmSandboxGate m_gate;
    std::string m_worker;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTCLASS_H
