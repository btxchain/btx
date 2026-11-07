// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ROLLADMIT_H
#define BTX_MODELNET_SWARM_ROLLADMIT_H

#include <string>

namespace modelnet {

struct SwarmRollAdmit {
    std::string example_id;
    bool private_data{false};
    bool rights_grant{false};
    bool credential{false};
    bool source_evidence{false};
    bool seen_before{false};
    bool want_train{false};
};

struct SwarmRollAdmitResult {
    std::string code;
    bool admitted{false};
    bool training{false};
};

/** A rollout example can be admitted locally and does not train. */
SwarmRollAdmitResult SwarmAdmitRolloutExample(const SwarmRollAdmit& example, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ROLLADMIT_H
