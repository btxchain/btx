// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ROLLOUT_H
#define BTX_MODELNET_SWARM_ROLLOUT_H

#include <string>

namespace modelnet {

/**
 * A private conversation does not become a training example unless a separate
 * rights grant and source evidence are both present. Credentials never do.
 * This function does not train and does not move bytes.
 */
bool SwarmAdmitRollout(const std::string& example_id, const std::string& origin, bool rights_authorized,
                       const std::string& source_evidence, bool seen_before, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ROLLOUT_H
