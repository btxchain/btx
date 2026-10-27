// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hostinterp.h>

namespace modelnet {

bool SwarmHostInterp::Admit(const std::string& job, const std::string& interpreter, bool host_path, std::string& err)
{
    if (job.empty() || interpreter.empty()) {
        err = "INTERP";
        return false;
    }
    if (m_jobs.find(job) != m_jobs.end()) {
        err = "REPLAY";
        return false;
    }
    if (host_path) {
        err = "HOST";
        return false;
    }
    m_jobs.insert(job);
    err.clear();
    return true;
}

bool SwarmHostInterp::admitted(const std::string& job) const
{
    return m_jobs.find(job) != m_jobs.end();
}

bool SwarmHostInterp::launched() const
{
    return false;
}

} // namespace modelnet
