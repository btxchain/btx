// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dlgrant.h>

namespace modelnet {

SwarmDownloadGrantResult SwarmNoteDownloadGrant(const SwarmDownloadGrant& grant, std::string& err)
{
    SwarmDownloadGrantResult result;
    result.training_allowed = false;
    if (grant.license_id.empty()) {
        result.code = "GRANT";
        err = "GRANT";
        return result;
    }
    if (grant.want_train && !grant.operator_grant) {
        result.code = "NOT_TRAINING";
        err = "NOT_TRAINING";
        return result;
    }
    if (grant.want_train) {
        result.training_allowed = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    result.training_allowed = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
