// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_incident.h>

namespace modelnet {

bool SwarmFreezePoisoning(SwarmIncident& incident, std::string& err)
{
    incident.frozen = true;
    incident.evidence_retained = true;
    incident.prior_checkpoint_preserved = true;
    incident.new_work_halted = true;
    incident.identity_remapped = false;
    err.clear();
    return true;
}

bool SwarmNoteKeyCompromise(SwarmIncident& incident, bool remap_history, std::string& err)
{
    if (remap_history) {
        incident.identity_remapped = false;
        err = "IDENTITY_REMAP";
        return false;
    }
    incident.frozen = true;
    incident.new_work_halted = true;
    incident.identity_remapped = false;
    incident.prior_checkpoint_preserved = true;
    err.clear();
    return true;
}

bool SwarmFreezeReorg(SwarmIncident& incident, std::string& err)
{
    incident.frozen = true;
    incident.new_work_halted = true;
    incident.earned_kept = true;
    incident.prior_checkpoint_preserved = true;
    err.clear();
    return true;
}

} // namespace modelnet
