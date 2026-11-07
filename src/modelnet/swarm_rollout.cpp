// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rollout.h>

#include <modelnet/swarm_frontier.h>

namespace modelnet {

bool SwarmAdmitRollout(const std::string& example_id, const std::string& origin, bool rights_authorized,
                       const std::string& source_evidence, bool seen_before, std::string& err)
{
    if (example_id.empty() || origin.empty()) {
        err = "ROLLOUT";
        return false;
    }
    if (seen_before) {
        err = "REPLAY";
        return false;
    }
    if (origin == "credential") {
        err = "CREDENTIAL";
        return false;
    }
    if (origin == "public_trajectory" || origin == "synthetic_trajectory") {
        if (source_evidence.empty()) {
            err = "EVIDENCE";
            return false;
        }
        return SwarmContributionKind(origin, err);
    }
    if (origin == "licensed") {
        if (!rights_authorized || source_evidence.empty()) {
            err = "RIGHTS";
            return false;
        }
        err.clear();
        return true;
    }
    if (origin == "private_conversation" || origin == "private_repo" || origin == "restricted_dataset" ||
        origin == "proprietary_prompt") {
        if (!rights_authorized || source_evidence.empty()) {
            err = "PRIVATE_DATA";
            return false;
        }
        err.clear();
        return true;
    }
    err = "ROLLOUT";
    return false;
}

} // namespace modelnet
