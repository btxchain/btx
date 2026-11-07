// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FOLLOW_H
#define BTX_MODELNET_SWARM_FOLLOW_H

#include <string>

namespace modelnet {

/**
 * Follow stages a compatible candidate. Pin and Refuse keep the previous head.
 * An incompatible checkpoint or recipe changes nothing.
 */
bool SwarmStagePolicy(std::string& active, std::string& staged, const std::string& policy, const std::string& candidate,
                      const std::string& local_checkpoint, const std::string& local_recipe,
                      const std::string& candidate_checkpoint, const std::string& candidate_recipe, bool& staged_now,
                      std::string& err);

} // namespace modelnet

#endif
