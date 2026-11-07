// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_INCIDENT_H
#define BTX_MODELNET_SWARM_INCIDENT_H

#include <string>

namespace modelnet {

/**
 * Local incident record. Freezing stops new work. It does not erase a prior
 * checkpoint or an earned obligation, and it does not remap identity history.
 * Nothing here signs or broadcasts.
 */
struct SwarmIncident {
    bool frozen{false};
    bool evidence_retained{false};
    bool prior_checkpoint_preserved{false};
    bool earned_kept{false};
    bool new_work_halted{false};
    bool identity_remapped{false};
};

/** Freeze the candidate, keep evidence and the prior checkpoint, halt new work. */
bool SwarmFreezePoisoning(SwarmIncident& incident, std::string& err);

/**
 * Revoke future use of the principal. remap_history is IDENTITY_REMAP and
 * changes nothing. A replacement is staged only as a flag the caller reads
 * from new_work_halted; this function does not invent a new principal id.
 */
bool SwarmNoteKeyCompromise(SwarmIncident& incident, bool remap_history, std::string& err);

/** Freeze new financial commitments. Earned rows stay. */
bool SwarmFreezeReorg(SwarmIncident& incident, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_INCIDENT_H
