// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault12.h>

#include <string>

namespace modelnet {

SwarmFault12Result SwarmRecoverFault12(const SwarmFault12& in, std::string& err)
{
    SwarmFault12Result out;
    // Conflicting reports settle nothing and move no atoms.
    out.settled = false;
    out.atoms_moved = 0;
    out.broadcast = false;
    if (in.report_id.empty()) {
        out.code = "REPORT";
        out.settled = false;
        out.atoms_moved = 0;
        out.broadcast = false;
        err = "REPORT";
        return out;
    }
    if (in.conflict || !in.distinct_evaluators || !in.distinct_domains) {
        out.code = "QUORUM";
        out.settled = false;
        out.atoms_moved = 0;
        out.broadcast = false;
        err = "QUORUM";
        return out;
    }
    if (in.want_settle) {
        out.code = "HELD";
        out.settled = false;
        out.atoms_moved = 0;
        out.broadcast = false;
        err.clear();
        return out;
    }
    out.code = "NOTED";
    out.settled = false;
    out.atoms_moved = 0;
    out.broadcast = false;
    err.clear();
    return out;
}

} // namespace modelnet
