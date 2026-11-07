// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_datasetgrant.h>

namespace modelnet {

// Training stays off unless a dataset grant is present and not withdrawn. This check does not start it.
SwarmDatasetGrantResult SwarmCheckDatasetGrant(const SwarmDatasetGrant& grant, std::string& err)
{
    SwarmDatasetGrantResult result;
    result.training = false;
    if (grant.grant_id.empty()) {
        result.code = "GRANT";
        err = "GRANT";
        result.training = false;
        return result;
    }
    if (!grant.present) {
        result.code = "DATASET";
        err = "DATASET";
        result.training = false;
        return result;
    }
    if (grant.withdrawn) {
        result.code = "DATASET";
        err = "DATASET";
        result.training = false;
        return result;
    }
    if (grant.want_train) {
        result.code = "HELD";
        err = "HELD";
        result.training = false;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.training = false;
    return result;
}

} // namespace modelnet
