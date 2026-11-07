// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_HOSTINTERP_H
#define BTX_MODELNET_SWARM_HOSTINTERP_H

#include <set>
#include <string>

namespace modelnet {

/**
 * A host interpreter is refused. launched stays false. This does not
 * exec a process.
 *
 * An empty job or an empty interpreter is INTERP and stores nothing.
 * A job already stored is REPLAY and leaves the first admission.
 * host_path true is HOST and stores nothing. Otherwise the job is
 * stored, err is cleared, and Admit returns true.
 */
class SwarmHostInterp {
public:
    bool Admit(const std::string& job, const std::string& interpreter, bool host_path, std::string& err);
    bool admitted(const std::string& job) const;
    bool launched() const;

private:
    std::set<std::string> m_jobs;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_HOSTINTERP_H
