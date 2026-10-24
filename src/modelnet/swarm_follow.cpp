// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_follow.h>

namespace modelnet {

bool SwarmStagePolicy(std::string& active, std::string& staged, const std::string& policy, const std::string& candidate,
                      const std::string& local_checkpoint, const std::string& local_recipe,
                      const std::string& candidate_checkpoint, const std::string& candidate_recipe, bool& staged_now,
                      std::string& err)
{
    staged_now = false;
    if (policy != "Follow" && policy != "Pin" && policy != "Refuse") {
        err = "POLICY";
        return false;
    }
    if (candidate.empty() || local_checkpoint.empty() || local_recipe.empty()) {
        err = "HEAD";
        return false;
    }
    if (candidate_checkpoint != local_checkpoint || candidate_recipe != local_recipe) {
        err = "INCOMPATIBLE";
        return false;
    }
    if (policy == "Follow") {
        staged = candidate;
        staged_now = true;
    }
    (void)active;
    err.clear();
    return true;
}

} // namespace modelnet
