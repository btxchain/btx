// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mandate0.h>

#include <cstdint>

namespace modelnet {

SwarmMandateSpendResult SwarmNoteMandateSpend(const SwarmMandateSpend& spend, std::string& err)
{
    SwarmMandateSpendResult result;
    result.automatic_spend = 0;
    if (spend.mandate_id.empty() || spend.bound_atoms < 1 || spend.requested_atoms <= 0) {
        result.automatic_spend = 0;
        result.code = "MANDATE";
        err = "MANDATE";
        return result;
    }
    if (!spend.operator_signed) {
        result.automatic_spend = 0;
        result.code = "UNSIGNED";
        err = "UNSIGNED";
        return result;
    }
    if (spend.requested_atoms > spend.bound_atoms) {
        result.automatic_spend = 0;
        result.code = "BOUND";
        err = "BOUND";
        return result;
    }
    // A signed bounded mandate in this note does not arm spending.
    // Nothing is signed and nothing is broadcast.
    result.automatic_spend = 0;
    result.code = "HELD";
    err.clear();
    return result;
}

} // namespace modelnet
