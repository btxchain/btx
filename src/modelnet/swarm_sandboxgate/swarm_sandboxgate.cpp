// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/swarm_sandboxgate.h>

#include <modelnet/swarm_sandboxgate/act.h>
#include <modelnet/swarm_sandboxgate/grant.h>
#include <modelnet/swarm_sandboxgate/inspect.h>
#include <modelnet/swarm_sandboxgate/net.h>
#include <modelnet/swarm_sandboxgate/run.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmSandboxGate::Grant(const std::string& worker,
                             const std::string& path_prefix,
                             const std::vector<std::string>& capabilities,
                             bool network,
                             int64_t until_ms,
                             std::string& err)
{
    return SwarmSandboxGateGrantApply(m_book, worker, path_prefix, capabilities, network, until_ms, err);
}

bool SwarmSandboxGate::Act(const std::string& worker,
                           const std::string& path,
                           const std::string& capability,
                           int64_t now_ms,
                           std::string& err)
{
    return SwarmSandboxGateActApply(m_book, m_journal, worker, path, capability, now_ms, err);
}

bool SwarmSandboxGate::Net(const std::string& worker, const std::string& host_id, int64_t now_ms, std::string& err)
{
    return SwarmSandboxGateNetPermit(m_book, worker, host_id, now_ms, err);
}

bool SwarmSandboxGate::Run(const std::string& worker, std::string& err)
{
    return SwarmSandboxGateRunRefuse(worker, err);
}

bool SwarmSandboxGate::granted(const std::string& worker) const
{
    return SwarmSandboxGateGranted(m_book, worker);
}

std::size_t SwarmSandboxGate::action_count() const
{
    return SwarmSandboxGateActionCount(m_journal);
}

bool SwarmSandboxGate::network_permitted(const std::string& worker, int64_t now_ms) const
{
    return SwarmSandboxGateNetworkPermitted(m_book, worker, now_ms);
}

bool SwarmSandboxGate::launched() const
{
    return m_quiet.launched();
}

bool SwarmSandboxGate::connected() const
{
    return m_quiet.connected();
}

bool SwarmSandboxGate::gpu() const
{
    return m_quiet.gpu();
}

int64_t SwarmSandboxGate::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

std::string SwarmSandboxGate::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

} // namespace modelnet
