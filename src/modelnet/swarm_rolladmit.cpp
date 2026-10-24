// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rolladmit.h>

namespace modelnet {

// A rollout example can be admitted locally and does not train.
SwarmRollAdmitResult SwarmAdmitRolloutExample(const SwarmRollAdmit& example, std::string& err)
{
    SwarmRollAdmitResult result;
    result.training = false;
    result.admitted = false;

    if (example.example_id.empty()) {
        result.code = "EXAMPLE";
        err = "EXAMPLE";
        result.admitted = false;
        result.training = false;
        return result;
    }
    if (example.credential) {
        result.code = "CREDENTIAL";
        err = "CREDENTIAL";
        result.admitted = false;
        result.training = false;
        return result;
    }
    if (example.private_data && !example.rights_grant) {
        result.code = "PRIVATE_DATA";
        err = "PRIVATE_DATA";
        result.admitted = false;
        result.training = false;
        return result;
    }
    if (example.seen_before) {
        result.code = "REPLAY";
        err = "REPLAY";
        result.admitted = false;
        result.training = false;
        return result;
    }
    if (!example.source_evidence) {
        result.code = "EVIDENCE";
        err = "EVIDENCE";
        result.admitted = false;
        result.training = false;
        return result;
    }
    if (example.want_train) {
        result.code = "HELD";
        err = "HELD";
        result.admitted = true;
        result.training = false;
        return result;
    }

    result.code = "NOTED";
    err.clear();
    result.admitted = true;
    result.training = false;
    return result;
}

} // namespace modelnet
