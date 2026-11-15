// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_assurance.h>

namespace modelnet {

SwarmAssuranceResult SwarmNoteAssurance(const SwarmAssurance& note, std::string& err)
{
    SwarmAssuranceResult result;
    result.work_proof = false;
    if (note.channel_id.empty()) {
        result.code = "ASSURANCE";
        result.work_proof = false;
        result.assurance.clear();
        err = "ASSURANCE";
        return result;
    }
    // A cumulative channel is not proof of work. Nothing is mined
    // and nothing is broadcast.
    if (note.want_work_proof) {
        result.code = "NOT_WORK_PROOF";
        result.work_proof = false;
        result.assurance = "CUMULATIVE_NOT_WORK_PROOF";
        err = "NOT_WORK_PROOF";
        return result;
    }
    result.code = "NOTED";
    result.work_proof = false;
    result.assurance = "CUMULATIVE_NOT_WORK_PROOF";
    err.clear();
    return result;
}

} // namespace modelnet
