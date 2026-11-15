// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradleak.h>

namespace modelnet {

SwarmGradientExport SwarmExportGradient(bool raw_gradient, bool same_tenant, bool authorized,
                                        bool claims_training_or_gradients, std::string& err)
{
    SwarmGradientExport result;
    result.contribution = false;
    result.bytes_moved = false;
    if (raw_gradient) {
        result.allowed = false;
        result.code = "GRADIENT_PRIVATE";
        err = "GRADIENT_PRIVATE";
        return result;
    }
    if (claims_training_or_gradients) {
        result.allowed = false;
        result.code = "CONTRIBUTION";
        err = "CONTRIBUTION";
        return result;
    }
    if (!same_tenant || !authorized) {
        result.allowed = false;
        result.code = "TENANT";
        err = "TENANT";
        return result;
    }
    result.allowed = true;
    result.code = "OK";
    err.clear();
    return result;
}

} // namespace modelnet
